/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2025 Scott Moreau
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <string>
#include <sys/wait.h>
#include <wayfire/core.hpp>
#include <wayfire/view.hpp>
#include <wayfire/plugin.hpp>
#include <wayfire/output.hpp>
#include <wayfire/render-manager.hpp>
#include <wayfire/per-output-plugin.hpp>
#include <wayfire/signal-definitions.hpp>
#include <wayfire/nonstd/wlroots-full.hpp>
#include <linux/input-event-codes.h>

#include <ogon/backend.h>
#include <ogon/dmgbuf.h>
#include <ogon/version.h>
#include <ogon/service.h>

#include <freerdp/freerdp.h>
#include <freerdp/update.h>
#include <freerdp/input.h>
#include <freerdp/locale/keyboard.h>
#include <freerdp/server/rdpei.h>

#include <winpr/input.h>
#include <winpr/stream.h>
#include <winpr/collections.h>

extern "C"
{
#include <wlr/backend/multi.h>
}

#include <GLES2/gl2.h>
#include <GLES2/gl2ext.h>

namespace wf
{
namespace ogon
{
static const struct wlr_pointer_impl pointer_impl = {
    .name = "ogon-pointer",
};

static void led_update(wlr_keyboard *keyboard, uint32_t leds)
{}

static const struct wlr_keyboard_impl keyboard_impl = {
    .name = "ogon-keyboard",
    .led_update = led_update,
};

class ogon_output_cdata : public wf::custom_data_t
{
  public:
    /* For handling output layout and mode changes */
    wf::signal::connection_t<wf::output_configuration_changed_signal> output_changed;
    /* For handling output commits */
    wf::wl_listener_wrapper output_commit;
    /* For handling batched regions and last output buffer damage regions */
    wf::region_t damage, last_damage;
};

class rdp_plugin : public wf::plugin_interface_t
{
    struct ogon_message_process
    {
        wl_event_source *event_source;
        rdp_plugin *plugin;
    };

    wlr_pointer pointer;
    wlr_keyboard keyboard;
    wlr_backend *backend;
    void *dmg_buf     = NULL;
    RDP_RECT *rdpRect = NULL;
    int screen_n_rects  = 0;
    int pending_outputs = 0;
    int pending_shm_id  = -1;
    ogon_msg_framebuffer_info rds_fb_infos;

  public:
    void *ogon_buffer = NULL;
    ogon_backend_service *ogon_service;
    wl_event_source *server_event_source = NULL;
    wl_event_source *client_event_source = NULL;

    void init() override
    {
        int session_id = 0;
        std::string session_id_prefix    = "--session-id=";
        std::string output_width_prefix  = "--width=";
        std::string output_height_prefix = "--height=";
        auto argc = wf::get_core().argc;
        auto argv = wf::get_core().argv;
        for (int i = 0; i < argc; i++)
        {
            if (!strncmp(argv[i], session_id_prefix.c_str(), strlen(session_id_prefix.c_str())))
            {
                session_id = atoi(argv[i] + strlen(session_id_prefix.c_str()));
            } else if (!strncmp(argv[i], output_width_prefix.c_str(), strlen(output_width_prefix.c_str())))
            {
                rds_fb_infos.width = atoi(argv[i] + strlen(output_width_prefix.c_str()));
            } else if (!strncmp(argv[i], output_height_prefix.c_str(), strlen(output_height_prefix.c_str())))
            {
                rds_fb_infos.height = atoi(argv[i] + strlen(output_height_prefix.c_str()));
            }
        }

        LOGI("session-id: ", session_id);
        LOGI("requested size: ", rds_fb_infos.width, "x", rds_fb_infos.height);
        ogon_service = ogon_service_new(session_id, "Weston");
        ogon_service_set_callbacks(ogon_service, &rds_callbacks);
        ogon_service_bind_endpoint(ogon_service);
        auto loop = wf::get_core().ev_loop;
        server_event_source = wl_event_loop_add_fd(loop, ogon_service_server_fd(ogon_service),
            WL_EVENT_READABLE, ogon_listener_activity, this);

        /* Output */
        rds_fb_infos.width = rds_fb_infos.height = 0;
        for (auto& o : wf::get_core().output_layout->get_outputs())
        {
            auto og = o->get_layout_geometry();
            LOGI("output: ", og.x, ",", og.y, " ", og.width, "x", og.height);
            rds_fb_infos.width  = std::max(og.x + og.width, int(rds_fb_infos.width));
            rds_fb_infos.height = std::max(og.y + og.height, int(rds_fb_infos.height));
            add_hook(o);
        }

        rds_fb_infos.bitsPerPixel  = 32;
        rds_fb_infos.bytesPerPixel = 4;
        rds_fb_infos.userId   = (UINT32)getuid();
        rds_fb_infos.scanline = rds_fb_infos.width * 4;
        rds_fb_infos.multiseatCapable = 0;
        LOGI("screens size: ", rds_fb_infos.width, "x", rds_fb_infos.height);

        /* Input */
        backend = wlr_headless_backend_create(wf::get_core().ev_loop);
        wlr_multi_backend_add(wf::get_core().backend, backend);
        wlr_pointer_init(&pointer, &pointer_impl, "ogon_pointer");
        wlr_keyboard_init(&keyboard, &keyboard_impl, "ogon_keyboard");
        wl_signal_emit_mutable(&backend->events.new_input, &pointer.base);
        wl_signal_emit_mutable(&backend->events.new_input, &keyboard.base);
        if (wf::get_core().get_current_state() == compositor_state_t::RUNNING)
        {
            wlr_backend_start(backend);
        }
    }

    /* Add commit event and output_changed handlers and damage each output */
    void add_hook(wf::output_t *output)
    {
        /* Get our custom data object that is associated with the output */
        auto cdata = output->get_data_safe<ogon_output_cdata>();

        /* Callback for output commit handler. This happens after each
         * output frame has been rendered.
         */
        cdata->output_commit.set_callback([=] (void *data)
        {
            int n_rects;
            auto ev = (wlr_output_event_commit*)data;
            if (!ev || !ev->state || !ev->state->buffer)
            {
                return;
            }

            /* If the compositor submitted damage, batch it by unioning
             * it with the rest of the unprocessed damage. We must wait
             * for ogon to submit a sync request and then copy the batched
             * damage and the last damage to the ogon output buffer. The
             * reason for the need to copy last damage region additionally,
             * is that the ogon output buffer contains old data from the
             * last frame, and these regions must be updated as well to
             * avoid artifacts.
             */
            if (ev->state->committed & WLR_OUTPUT_STATE_DAMAGE)
            {
                cdata->damage |= wf::region_t{(pixman_region32_t*)&ev->state->damage};
            }

            /* If ogon has issued a frame sync request, begin processing
             * the output's damaged regions.
             */
            if (pending_outputs)
            {
                /* We don't want to overwrite cdata->damage, so store the damage
                 * in a temporary region object. */
                wf::region_t combined_damage;
                /* The layout geometry is the same as relative geometry with the
                 * exception that the x,y position are both set to 0  with
                 * relative, while the position is that of the output layout
                 * with layout geometry.
                 */
                auto og = output->get_layout_geometry();
                /* The combined damage is set to the region of current damage,
                 * which has been batched since the last ogon frame sync request
                 * and the last damage region, so that the pixels needed in the
                 * ogon buffer get transfered. This is intersected with the output
                 * geometry so we don't have any out-of-bounds rects.
                 */
                combined_damage = (cdata->damage | cdata->last_damage) & wf::region_t{output->get_relative_geometry()};
                /* Get the number of rects in the combined damage region */
                pixman_region32_rectangles(combined_damage.to_pixman(), &n_rects);
                /* If there is damage, copy the pixels of the damaged region. */
                if (n_rects)
                {
                    /* If we already have the ogon damage buffer, ensure it matches
                     * the shm id sent in the ogon frame sync request. If it's not,
                     * drop the buffer to be reacquired.
                     */
                    if (this->dmg_buf)
                    {
                        if (ogon_dmgbuf_get_id(this->dmg_buf) != this->pending_shm_id)
                        {
                            ogon_dmgbuf_free(this->dmg_buf);
                            this->dmg_buf = 0;
                        }
                    }

                    /* If we do not have an ogon damage buffer at this point, try
                     * to acquire it using the shm id sent from the ogon frame sync
                     * request. Finally, get the pointer to the ogon buffer pixels
                     * from the damage buffer.
                     */
                    if (!this->dmg_buf)
                    {
                        this->dmg_buf = ogon_dmgbuf_connect(this->pending_shm_id);
                        if (!this->dmg_buf)
                        {
                            LOGI(__FUNCTION__, ": unable to bind shmId=", this->pending_shm_id);
                            return;
                        }

                        ogon_buffer = ogon_dmgbuf_get_data(this->dmg_buf);
                    }

                    /* If the ogon output buffer is NULL, bail. */
                    if (!ogon_buffer)
                    {
                        goto out;
                    }

                    /* Get the rects pointer, so we can define each rect we're
                     * copying into the buffer. This is only reset after all
                     * outputs have been committed.
                     */
                    if (!rdpRect)
                    {
                        rdpRect = ogon_dmgbuf_get_rects(this->dmg_buf, NULL);
                    }

                    /* If there are too many rects, just use the extents of the region. */
                    if (n_rects > (int)ogon_dmgbuf_get_max_rects(this->dmg_buf))
                    {
                        /* Since we are using this variable to accumulate the number of
                         * rects that will be used to update the ogon screen buffer,
                         * set it accordingly.
                         */
                        n_rects = 1;
                        /* Get the extents */
                        auto extents = combined_damage.get_extents();
                        /* Make a box from the extent values */
                        wlr_box b = wlr_box{extents.x1, extents.y1, extents.x2 - extents.x1, extents.y2 - extents.y1};
                        /* Read the pixels from the relevant area and copy them into the
                         * ogon output buffer.
                         */
                        OpenGL::render_begin();
                        GL_CALL(glBindFramebuffer(GL_READ_FRAMEBUFFER,
                            wlr_gles2_renderer_get_buffer_fbo(wf::get_core().renderer, ev->state->buffer)));
                        rdpRect->x     = og.x + b.x;
                        rdpRect->y     = og.y + b.y;
                        rdpRect->width = b.width;
                        rdpRect->height = b.height;
                        std::vector<unsigned char> pixels(b.width * b.height * 4);
                        /* Read the pixels from the wayfire framebuffer */
                        GL_CALL(glReadPixels(b.x, b.y, b.width, b.height,
                            GL_BGRA_EXT, GL_UNSIGNED_BYTE, pixels.data()));
                        /* Copy them one horizontal line at a time */
                        for (int y = rdpRect->y; y < rdpRect->y + rdpRect->height; y++)
                        {
                            memcpy((unsigned char*)ogon_buffer + (rdpRect->x * 4) +
                                (y * rds_fb_infos.scanline),
                                pixels.data() + ((y - (og.y + b.y)) * b.width * 4), b.width * 4);
                        }

                        /* Iterate the rect pointer in case there are other outputs. */
                        rdpRect++;

                        OpenGL::render_end();
                    } else
                    {
                        /* In this case, we copy all the rects in the damage region. */
                        OpenGL::render_begin();
                        GL_CALL(glBindFramebuffer(GL_READ_FRAMEBUFFER,
                            wlr_gles2_renderer_get_buffer_fbo(wf::get_core().renderer, ev->state->buffer)));
                        for (auto& box : combined_damage)
                        {
                            auto b     = wlr_box_from_pixman_box(box);
                            rdpRect->x = og.x + b.x;
                            rdpRect->y = og.y + b.y;
                            rdpRect->width  = b.width;
                            rdpRect->height = b.height;
                            std::vector<unsigned char> pixels(b.width * b.height * 4);
                            /* Read the pixels from the wayfire framebuffer */
                            GL_CALL(glReadPixels(b.x, b.y, b.width, b.height,
                                GL_BGRA_EXT, GL_UNSIGNED_BYTE, pixels.data()));
                            /* Copy them one horizontal line at a time */
                            for (int y = rdpRect->y; y < rdpRect->y + rdpRect->height; y++)
                            {
                                memcpy((unsigned char*)ogon_buffer + (rdpRect->x * 4) +
                                    (y * rds_fb_infos.scanline),
                                    pixels.data() + ((y - (og.y + b.y)) * b.width * 4), b.width * 4);
                            }

                            /* Iterate the rect pointer for each rect in the damage region.
                             * We want to iterate even after the last rect in case there are
                             * other outputs to be processed. */
                            rdpRect++;
                        }

                        OpenGL::render_end();
                    }

                    /* Keep track of how many rects we have copied */
                    screen_n_rects += n_rects;
                }

                /* The ogon frame sync request sets pending_outputs to the number of
                 * wayfire outputs. This commit function is called once per output,
                 * so decrement the variable so we know when the last output has been
                 * processed.
                 */
                pending_outputs--;

                /* Once all of the output pixels have been copied into the ogon screen buffer,
                 * set the total number of rects and send the sync reply message.
                 */
                if (!pending_outputs)
                {
                    ogon_dmgbuf_set_num_rects(this->dmg_buf, screen_n_rects);

                    ogon_msg_framebuffer_sync_reply rds_sync_reply =
                    {
                        .bufferId = this->pending_shm_id,
                    };
                    ogon_service_write_message(ogon_service, OGON_SERVER_FRAMEBUFFER_SYNC_REPLY,
                        (ogon_message*)&rds_sync_reply);

                    /* Reset the damage since we have processed it for all outputs. */
                    for (auto& o : wf::get_core().output_layout->get_outputs())
                    {
                        auto custom_data = o->get_data_safe<ogon_output_cdata>();
                        custom_data->damage.clear();
                    }

                    /* Reset the total number of screen rects and the ogon rect pointer. */
                    screen_n_rects = 0;
                    rdpRect = NULL;
                }
            }

            out:
            /* Finally, store the current batched damage unconditonally. */
            cdata->last_damage = cdata->damage;
        });

        cdata->output_changed.set_callback([=] (wf::output_configuration_changed_signal *ev)
        {
            rds_fb_infos.width = rds_fb_infos.height = 0;
            for (auto& o : wf::get_core().output_layout->get_outputs())
            {
                auto og = o->get_layout_geometry();
                LOGI("output: ", og.x, ",", og.y, " ", og.width, "x", og.height);
                rds_fb_infos.width  = std::max(og.x + og.width, int(rds_fb_infos.width));
                rds_fb_infos.height = std::max(og.y + og.height, int(rds_fb_infos.height));
            }

            ogon_send_shared_framebuffer(this);
        });

        cdata->output_commit.connect(&output->handle->events.commit);
        output->connect(&cdata->output_changed);
        output->render->damage_whole();
    }

    void rem_hook(wf::output_t *output)
    {
        auto cdata = output->get_data_safe<ogon_output_cdata>();
        cdata->output_commit.disconnect();
        cdata->output_changed.disconnect();
    }

    void do_key(uint32_t key, wl_keyboard_key_state state)
    {
        wlr_keyboard_key_event ev;
        ev.keycode = key;
        ev.state   = state;
        ev.update_state = true;
        ev.time_msec    = get_current_time();
        wlr_keyboard_notify_key(&keyboard, &ev);
    }

    void do_button(uint32_t button, wl_pointer_button_state state)
    {
        wlr_pointer_button_event ev;
        ev.pointer   = &pointer;
        ev.button    = button;
        ev.state     = state;
        ev.time_msec = get_current_time();
        wl_signal_emit(&pointer.events.button, &ev);
        wl_signal_emit(&pointer.events.frame, NULL);
    }

    void do_motion(double x, double y)
    {
        auto cursor = wf::get_core().get_cursor_position();

        wlr_pointer_motion_event ev;
        ev.pointer   = &pointer;
        ev.time_msec = get_current_time();
        ev.delta_x   = ev.unaccel_dx = x - cursor.x;
        ev.delta_y   = ev.unaccel_dy = y - cursor.y;
        wl_signal_emit(&pointer.events.motion, &ev);
        wl_signal_emit(&pointer.events.frame, NULL);
    }

    void do_axis(double value)
    {
        wlr_pointer_axis_event ev;
        ev.pointer   = &pointer;
        ev.time_msec = get_current_time();
        ev.source    = WL_POINTER_AXIS_SOURCE_WHEEL;
        ev.orientation = WL_POINTER_AXIS_VERTICAL_SCROLL;
        ev.relative_direction = WL_POINTER_AXIS_RELATIVE_DIRECTION_IDENTICAL;
        ev.delta = value;
        wl_signal_emit(&pointer.events.axis, &ev);
        wl_signal_emit(&pointer.events.frame, NULL);
    }

    int ogon_send_shared_framebuffer(rdp_plugin *p)
    {
        return ogon_service_write_message(p->ogon_service, OGON_SERVER_FRAMEBUFFER_INFO,
            (ogon_message*)&p->rds_fb_infos);
    }

    int rdsCapabilities(ogon_msg_capabilities *capabilities)
    {
        ogon_send_shared_framebuffer(this);
        return 1;
    }

    int rdsSynchronizeKeyboardEvent(DWORD flags, UINT32 clientId)
    {
        return 1;
    }

    int rdsScancodeKeyboardEvent(DWORD flags, DWORD code, DWORD keyboardType, UINT32 clientId)
    {
        do_key(ogon_rdp_scancode_to_evdev_code(flags, code, keyboardType),
            (flags & KBD_FLAGS_DOWN) ? WL_KEYBOARD_KEY_STATE_PRESSED : WL_KEYBOARD_KEY_STATE_RELEASED);
        return 1;
    }

    int rdsUnicodeKeyboardEvent(DWORD flags, DWORD code, UINT32 clientId)
    {
        do_key(code,
            (flags & KBD_FLAGS_DOWN) ? WL_KEYBOARD_KEY_STATE_PRESSED : WL_KEYBOARD_KEY_STATE_RELEASED);
        return 1;
    }

    void handle_mouse_event(DWORD flags, DWORD x, DWORD y, UINT32 clientId)
    {
        if (flags & PTR_FLAGS_MOVE)
        {
            do_motion(x, y);
        }

        if (flags & PTR_FLAGS_BUTTON1)
        {
            do_button(BTN_LEFT,
                (flags &
                    PTR_FLAGS_DOWN) ? WL_POINTER_BUTTON_STATE_PRESSED : WL_POINTER_BUTTON_STATE_RELEASED);
        } else if (flags & PTR_FLAGS_BUTTON2)
        {
            do_button(BTN_RIGHT,
                (flags &
                    PTR_FLAGS_DOWN) ? WL_POINTER_BUTTON_STATE_PRESSED : WL_POINTER_BUTTON_STATE_RELEASED);
        } else if (flags & PTR_FLAGS_BUTTON3)
        {
            do_button(BTN_MIDDLE,
                (flags &
                    PTR_FLAGS_DOWN) ? WL_POINTER_BUTTON_STATE_PRESSED : WL_POINTER_BUTTON_STATE_RELEASED);
        }

        if (flags & PTR_FLAGS_WHEEL)
        {
            double value;

            value = -((flags & 0xff) / 30.0);
            if (flags & PTR_FLAGS_WHEEL_NEGATIVE)
            {
                value *= -1.0;
            }

            do_axis(value);
        }
    }

    int rdsMouseEvent(DWORD flags, DWORD x, DWORD y, UINT32 clientId)
    {
        handle_mouse_event(flags, x, y, clientId);
        return 1;
    }

    int rdsExtendedMouseEvent(DWORD flags, DWORD x, DWORD y, UINT32 clientId)
    {
        handle_mouse_event(flags, x, y, clientId);
        return 1;
    }

    int handle_framebuffer_sync_request(INT32 buffer_id)
    {
        /* A framebuffer sync request was issued by the ogon server.
         * Store the shm id to use the associated buffer later, in
         * output commit handler.
         */
        pending_shm_id = buffer_id;

        /* If there is a pending sync request, return early. */
        if (pending_outputs)
        {
            return 1;
        }

        /* Set pending_outputs to the number of wayfire outputs.
         * This will cause output commit events to read the pixels
         * from the outputs and copy them to the ogon screen buffer.
         */
        pending_outputs = wf::get_core().output_layout->get_outputs().size();

        return 1;
    }

    int rdsFramebufferSyncRequest(INT32 buffer_id)
    {
        return handle_framebuffer_sync_request(buffer_id);
    }

    int rdsImmediateSyncRequest(INT32 buffer_id)
    {
        return handle_framebuffer_sync_request(buffer_id);
    }

    int rdsSbp(ogon_msg_sbp_reply *msg)
    {
        return 1;
    }

    int rdsSeatNew(ogon_msg_seat_new *seatNew)
    {
        return 1;
    }

    int rdsSeatRemoved(UINT32 clientId)
    {
        return 1;
    }

    int write_pipe_rds_client_message(int fd, BYTE *value, int size)
    {
        int written;
        int totalWritten = 0;

        while (totalWritten != size)
        {
            written = write(fd, value + totalWritten, size - totalWritten);
            if (written < 0)
            {
                LOGI(__FUNCTION__, ": socket(", fd, ") for message display closed unexpected");
                close(fd);
                return -1;
            }

            totalWritten += written;
        }

        return written;
    }

    int read_pipe_rds_client_message(int fd, BYTE *buffer, int size)
    {
        int currentRead;
        int totalBytes = 0;
        while (totalBytes != size)
        {
            currentRead = read(fd, buffer + totalBytes, size - totalBytes);
            if (currentRead < 1)
            {
                LOGI(__FUNCTION__, ": socket(", fd, ") for message display closed unexpected");
                close(fd);
                return 0;
            }

            totalBytes += currentRead;
        }

        return 1;
    }

    static int ogon_message_process_activity(int fd, uint32_t mask, void *data)
    {
        struct ogon_message_process *process = (struct ogon_message_process*)data;
        rdp_plugin *p = process->plugin;
        int result, retValue;
        UINT32 message_id;
        ogon_msg_message_reply rep;

        retValue = -1;
        if (!p->read_pipe_rds_client_message(fd, (BYTE*)&result, sizeof(result)))
        {
            goto out;
        }

        if (!p->read_pipe_rds_client_message(fd, (BYTE*)&message_id, sizeof(message_id)))
        {
            goto out;
        }

        close(fd);

        LOGI(__FUNCTION__, ": sending message with messageid (", message_id, ") and result(", result, ")");

        rep.message_id = message_id;
        rep.result     = (UINT32)result;

        if (!ogon_service_write_message(process->plugin->ogon_service, OGON_SERVER_MESSAGE_REPLY,
            (ogon_message*)&rep))
        {
            LOGI("error sending user message reply");
        } else
        {
            retValue = 0;
        }

out:
        wl_event_source_remove(process->event_source);
        free(process);
        return retValue;
    }

#define BUFFER_SIZE_MESSAGE 4 * 1024

    static int ogon_show_user_message(ogon_msg_message *msg)
    {
        int retVal = 0;
        char buffer[BUFFER_SIZE_MESSAGE];
        char executableName[BUFFER_SIZE_MESSAGE];

        snprintf(executableName, BUFFER_SIZE_MESSAGE, "ogon-message");

        snprintf(buffer, BUFFER_SIZE_MESSAGE,
            "%s -platform wayland %u %u %u %u \"%s\" \"%s\" \"%s\" \"%s\" \"%s\"",
            executableName,
            msg->message_id, msg->message_type, msg->style, msg->timeout,
            msg->parameter_num > 0 ? msg->parameter1 : "",
            msg->parameter_num > 1 ? msg->parameter2 : "",
            msg->parameter_num > 2 ? msg->parameter3 : "",
            msg->parameter_num > 3 ? msg->parameter4 : "",
            msg->parameter_num > 4 ? msg->parameter5 : "");
        retVal = system(buffer);
        if (!WIFEXITED(retVal))
        {
            return -1;
        }

        retVal = WEXITSTATUS(retVal);
        if (retVal == 255)
        {
            retVal = -1;
        }

        return retVal;
    }

    int rdsUserMessage(void *data, ogon_msg_message *msg)
    {
        pid_t pid;
        int status;
        int retVal = 0;
        int fd[2];
        ogon_message_process *process;
        rdp_plugin *p = (rdp_plugin*)data;

        process = (struct ogon_message_process*)malloc(sizeof(*process));
        if (!process)
        {
            LOGI("unable to allocate process tracking info");
            return false;
        }

        process->plugin = p;

        status = pipe(fd);
        if (status != 0)
        {
            LOGI("%s: pipe creation failed ", __FUNCTION__);
            free(process);
            return false;
        }

        process->event_source = wl_event_loop_add_fd(wf::get_core().ev_loop,
            fd[0], WL_EVENT_READABLE, ogon_message_process_activity, process);
        if (!process->event_source)
        {
            LOGI("%s: unable to create event source ", __FUNCTION__);
            close(fd[0]);
            close(fd[1]);
            free(process);
            return false;
        }

        pid = fork();
        if (pid == 0)
        {
            /* child */
            if (fork() == 0)
            {
                /* Child process closes up input side of pipe */
                close(fd[0]);

                retVal = ogon_show_user_message(msg);

                write_pipe_rds_client_message(fd[1], (BYTE*)&retVal, sizeof(retVal));
                write_pipe_rds_client_message(fd[1], (BYTE*)&msg->message_id, sizeof(msg->message_id));

                close(fd[1]);
                exit(0);
            } else
            {
                exit(0);
            }
        } else
        {
            /* parent */
            waitpid(pid, &status, 0);

            /* Parent process closes up output side of pipe */
            close(fd[1]);
        }

        return 1;
    }

    void ogon_kill_client(rdp_plugin *p)
    {
        wl_event_source_remove(p->client_event_source);
        p->client_event_source = 0;

        ogon_service_kill_client(p->ogon_service);
    }

    static int ogon_client_activity(int fd, uint32_t mask, void *data)
    {
        rdp_plugin *p = (rdp_plugin*)data;

        if (!(mask & WL_EVENT_READABLE))
        {
            return 0;
        }

        switch (ogon_service_incoming_bytes(p->ogon_service, p))
        {
          case OGON_INCOMING_BYTES_OK:
          case OGON_INCOMING_BYTES_WANT_MORE_DATA:
            break;

          case OGON_INCOMING_BYTES_BROKEN_PIPE:
          case OGON_INCOMING_BYTES_INVALID_MESSAGE:
          default:
            LOGI("error treating incoming traffic\n");
            p->ogon_kill_client(p);
            break;
        }

        return 0;
    }

    static int ogon_listener_activity(int fd, uint32_t mask, void *data)
    {
        rdp_plugin *p = (rdp_plugin*)data;
        HANDLE client_handle;

        if (p->client_event_source)
        {
            LOGI("dropping existing client");
            p->ogon_kill_client(p);
        }

        client_handle = ogon_service_accept(p->ogon_service);
        if (client_handle && (client_handle != INVALID_HANDLE_VALUE))
        {
            ogon_msg_version version;
            BOOL ret;

            version.versionMajor = OGON_PROTOCOL_VERSION_MAJOR;
            version.versionMinor = OGON_PROTOCOL_VERSION_MINOR;

            char *backendCookie = getenv("OGON_BACKEND_COOKIE");
            if (backendCookie)
            {
                version.cookie = strdup(backendCookie);
                if (!version.cookie)
                {
                    LOGI("unable to duplicate backend cookie");
                    ogon_service_kill_client(p->ogon_service);
                    return 0;
                }
            } else
            {
                version.cookie = NULL;
            }

            ret = ogon_service_write_message(p->ogon_service, OGON_SERVER_VERSION_REPLY,
                (ogon_message*)&version);

            free(version.cookie);

            if (!ret)
            {
                LOGI("failed to write version message to stream");
                ogon_service_kill_client(p->ogon_service);
                return 0;
            }

            auto loop = wf::get_core().ev_loop;
            p->client_event_source = wl_event_loop_add_fd(loop, ogon_service_client_fd(p->ogon_service),
                WL_EVENT_READABLE, ogon_client_activity, p);
        }

        return 0;
    }

    ogon_client_interface rds_callbacks = {
        (pfn_ogon_client_capabilities) & wf::ogon::rdp_plugin::rdsCapabilities,
        (pfn_ogon_client_synchronize_keyboard_event) & wf::ogon::rdp_plugin::rdsSynchronizeKeyboardEvent,
        (pfn_ogon_client_scancode_keyboard_event) & wf::ogon::rdp_plugin::rdsScancodeKeyboardEvent,
        (pfn_ogon_client_unicode_keyboard_event) & wf::ogon::rdp_plugin::rdsUnicodeKeyboardEvent,
        (pfn_ogon_client_mouse_event) & wf::ogon::rdp_plugin::rdsMouseEvent,
        (pfn_ogon_client_extended_mouse_event) & wf::ogon::rdp_plugin::rdsExtendedMouseEvent,
        (pfn_ogon_client_framebuffer_sync_request) & wf::ogon::rdp_plugin::rdsFramebufferSyncRequest,
        (pfn_ogon_client_sbp) & wf::ogon::rdp_plugin::rdsSbp,
        (pfn_ogon_client_immediate_sync_request) & wf::ogon::rdp_plugin::rdsImmediateSyncRequest,
        (pfn_ogon_client_seat_new) & wf::ogon::rdp_plugin::rdsSeatNew,
        (pfn_ogon_client_seat_removed) & wf::ogon::rdp_plugin::rdsSeatRemoved,
        (pfn_ogon_client_message) & wf::ogon::rdp_plugin::rdsUserMessage
    };

    void fini() override
    {
        for (auto& o : wf::get_core().output_layout->get_outputs())
        {
            rem_hook(o);
        }

        wl_event_source_remove(server_event_source);
        ogon_service_free(ogon_service);
        wlr_pointer_finish(&pointer);
        wlr_keyboard_finish(&keyboard);
        wlr_multi_backend_remove(wf::get_core().backend, backend);
        wlr_backend_destroy(backend);
    }
};
}
}

DECLARE_WAYFIRE_PLUGIN(wf::ogon::rdp_plugin);
