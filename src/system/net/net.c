// MIT License

// Copyright (c) 2017 Vadim Grigoruk @nesbox // grigoruk@gmail.com

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include "net.h"
#include "defines.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#if defined(__EMSCRIPTEN__)

#include <emscripten/fetch.h>

typedef struct
{
    HttpGetCallback callback;
    void* calldata;
} FetchData;

struct Net
{
    emscripten_fetch_attr_t attr;
};

static void downloadSucceeded(emscripten_fetch_t *fetch) 
{
    FetchData* data = (FetchData*)fetch->userData;

    HttpGetData getData = 
    {
        .type = HttpGetDone,
        .done = 
        {
            .size = fetch->numBytes,
            .data = (u8*)fetch->data,
        },
        .calldata = data->calldata,
        .url = fetch->url,
    };

    data->callback(&getData);

    free(fetch->data);
    free(data);

    emscripten_fetch_close(fetch);
}

static void downloadFailed(emscripten_fetch_t *fetch) 
{
    FetchData* data = (FetchData*)fetch->userData;

    HttpGetData getData = 
    {
        .type = HttpGetError,
        .error = 
        {
            .code = fetch->status,
        },
        .calldata = data->calldata,
        .url = fetch->url,
    };

    data->callback(&getData);

    free(data);

    emscripten_fetch_close(fetch);
}

static void downloadProgress(emscripten_fetch_t *fetch) 
{
    FetchData* data = (FetchData*)fetch->userData;

    HttpGetData getData = 
    {
        .type = HttpGetProgress,
        .progress = 
        {
            .size = fetch->dataOffset + fetch->numBytes,
            .total = fetch->totalBytes,
        },
        .calldata = data->calldata,
        .url = fetch->url,
    };

    data->callback(&getData);
}

#else

#include <uv.h>
#include <http_parser.h>

struct Net
{
    char* host;
    char* path;

    HttpGetCallback callback;
    void* calldata;

    uv_tcp_t tcp;
    http_parser parser;

    struct
    {
        u8* data;
        s32 size;
        s32 total;
    } content;
};

static s32 onBody(http_parser* parser, const char *at, size_t length)
{
    Net* net = parser->data;

    net->content.data = realloc(net->content.data, net->content.size + length);
    memcpy(net->content.data + net->content.size, at, length);

    net->content.size += length;

    net->callback(&(HttpGetData) 
    {
        .calldata = net->calldata, 
        .type = HttpGetProgress, 
        .progress = {net->content.size, net->content.total}, 
        .url = net->path
    });

    return 0;
}

static s32 onMessageComplete(http_parser* parser)
{
    Net* net = parser->data;

    if (parser->status_code == HTTP_STATUS_OK)
    {
        net->callback(&(HttpGetData)
        {
            .calldata = net->calldata,
            .type = HttpGetDone,
            .done = { .data = net->content.data, .size = net->content.size },
            .url = net->path
        });

        free(net->content.data);
        free(net->path);
    }

    // if (!http_should_keep_alive(parser))
    uv_close((uv_handle_t*)&net->tcp, NULL);

    return 0;
}

static s32 onHeadersComplete(http_parser* parser)
{
    Net* net = parser->data;

    bool hasBody = parser->flags & F_CHUNKED || (parser->content_length > 0 && parser->content_length != ULLONG_MAX);

    ZEROMEM(net->content);
    net->content.total = parser->content_length;

    // !TODO: handle HTTP_STATUS_MOVED_PERMANENTLY here
    if (!hasBody || parser->status_code != HTTP_STATUS_OK)
        return 1;

    return 0;
}

static s32 onStatus(http_parser* parser, const char* at, size_t length)
{
    return parser->status_code != HTTP_STATUS_OK;
}

static void onError(Net* net, s32 code)
{
    net->callback(&(HttpGetData)
    {
        .calldata = net->calldata,
        .type = HttpGetError,
        .error = { .code = code }
    });

    uv_close((uv_handle_t*)&net->tcp, NULL);

    free(net->path);
}

static void allocBuffer(uv_handle_t *handle, size_t size, uv_buf_t *buf)
{
    buf->base = malloc(size);
    buf->len = size;
}

static void onResponse(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) 
{
    Net* net = stream->data;

    if(nread > 0)
    {
        static const http_parser_settings ParserSettings = 
        {
            .on_status = onStatus,
            .on_body = onBody,
            .on_message_complete = onMessageComplete,
            .on_headers_complete = onHeadersComplete,
        };

        s32 parsed = http_parser_execute(&net->parser, &ParserSettings, buf->base, nread);

        if(parsed != nread)
            onError(net, net->parser.status_code);

        free(buf->base);
    }
    else onError(net, 0);
}

static void onHeaderSent(uv_write_t *write, s32 status)
{
    Net* net = write->data;
    http_parser_init(&net->parser, HTTP_RESPONSE);
    net->parser.data = net;

    uv_stream_t* handle = write->handle;
    free(write);

    handle->data = net;
    uv_read_start(handle, allocBuffer, onResponse);
}

static void onConnect(uv_connect_t *req, s32 status)
{
    Net* net = req->data;

    char httpReq[2048];
    snprintf(httpReq, sizeof httpReq, "GET %s HTTP/1.1\nHost: %s\n\n", net->path, net->host);

    uv_buf_t http = uv_buf_init(httpReq, strlen(httpReq));

    uv_write(OBJCOPY((uv_write_t){.data = net}), req->handle, &http, 1, onHeaderSent);

    free(req);
}

static void onResolved(uv_getaddrinfo_t *resolver, s32 status, struct addrinfo *res)
{
    Net* net = resolver->data;

    if (res)
    {
        uv_tcp_connect(OBJCOPY((uv_connect_t){.data = net}), &net->tcp, res->ai_addr, onConnect);
        uv_freeaddrinfo(res);
    }
    else onError(net, 0);

    free(resolver);
}

#endif

void netGet(Net* net, const char* path, HttpGetCallback callback, void* calldata)
{
#if defined(__EMSCRIPTEN__)

    FetchData* data = OBJCOPY((FetchData)
    {
        .callback = callback,
        .calldata = calldata,
    });

    net->attr.userData = data;
    emscripten_fetch(&net->attr, path);

#else

    uv_loop_t* loop = uv_default_loop();

    net->callback = callback;
    net->calldata = calldata;
    net->path = strdup(path);

    uv_tcp_init(loop, &net->tcp);
    uv_getaddrinfo(loop, OBJCOPY((uv_getaddrinfo_t){.data = net}), onResolved, net->host, "80", NULL);

#endif
}

void netTick(Net *net)
{
#if !defined(__EMSCRIPTEN__)

    uv_run(uv_default_loop(), UV_RUN_NOWAIT);

#endif
}

Net* createNet(const char* host)
{
    Net* net = (Net*)malloc(sizeof(Net));

#if defined(__EMSCRIPTEN__)

    emscripten_fetch_attr_init(&net->attr);
    strcpy(net->attr.requestMethod, "GET");
    net->attr.attributes = EMSCRIPTEN_FETCH_LOAD_TO_MEMORY;
    net->attr.onsuccess = downloadSucceeded;
    net->attr.onerror = downloadFailed;
    net->attr.onprogress = downloadProgress;

#else

    memset(net, 0, sizeof(Net));
    if (net != NULL)
        net->host = strdup(host);

#endif

    return net;
}

void closeNet(Net* net)
{
#if !defined(__EMSCRIPTEN__)

    free(net->host);

#endif

    free(net);
}
