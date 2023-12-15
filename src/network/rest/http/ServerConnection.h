/**
* Digital Voice Modem - Host Software
* GPLv2 Open Source. Use is subject to license terms.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
*
* @package DVM / Host Software
*
*/
//
// Based on code from the CRUD project. (https://github.com/venediktov/CRUD)
// Licensed under the BPL-1.0 License (https://opensource.org/license/bsl1-0-html)
//
/*
*   Copyright (c) 2003-2013 Christopher M. Kohlhoff
*   Copyright (C) 2023 by Bryan Biedenkapp N2PLL
*
*   Permission is hereby granted, free of charge, to any person or organization
*   obtaining a copy of the software and accompanying documentation covered by
*   this license (the “Software”) to use, reproduce, display, distribute, execute,
*   and transmit the Software, and to prepare derivative works of the Software, and
*   to permit third-parties to whom the Software is furnished to do so, all subject
*   to the following:
*
*   The copyright notices in the Software and this entire statement, including the
*   above license grant, this restriction and the following disclaimer, must be included
*   in all copies of the Software, in whole or in part, and all derivative works of the
*   Software, unless such copies or derivative works are solely in the form of
*   machine-executable object code generated by a source language processor.
*
*   THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
*   INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
*   PURPOSE, TITLE AND NON-INFRINGEMENT. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR ANYONE
*   DISTRIBUTING THE SOFTWARE BE LIABLE FOR ANY DAMAGES OR OTHER LIABILITY, WHETHER IN
*   CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE
*   OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
#if !defined(__REST_HTTP__SERVER_CONNECTION_H__)
#define __REST_HTTP__SERVER_CONNECTION_H__

#include "Defines.h"
#include "network/rest/http/HTTPLexer.h"
#include "network/rest/http/HTTPPayload.h"
#include "Log.h"
#include "Utils.h"

#include <array>
#include <memory>
#include <utility>
#include <iterator>
#include <asio.hpp>

namespace network
{
    namespace rest
    {
        namespace http
        {
            // ---------------------------------------------------------------------------
            //  Class Prototypes
            // ---------------------------------------------------------------------------

            template<class> class ServerConnectionManager;

            // ---------------------------------------------------------------------------
            //  Class Declaration
            //      This class represents a single connection from a client.
            // ---------------------------------------------------------------------------

            template <typename RequestHandlerType>
            class ServerConnection : public std::enable_shared_from_this<ServerConnection<RequestHandlerType>> {
                typedef ServerConnection<RequestHandlerType> selfType;
                typedef std::shared_ptr<selfType> selfTypePtr;
                typedef ServerConnectionManager<selfTypePtr> ConnectionManagerType;
            public:
                /// <summary>Initializes a new instance of the ServerConnection class.</summary>
                explicit ServerConnection(asio::ip::tcp::socket socket, ConnectionManagerType& manager, RequestHandlerType& handler,
                    bool persistent = false) :
                    m_socket(std::move(socket)),
                    m_connectionManager(manager),
                    m_requestHandler(handler),
                    m_lexer(HTTPLexer(false)),
                    m_persistent(persistent)
                {
                    /* stub */
                }
                /// <summary>Initializes a copy instance of the ServerConnection class.</summary>
                ServerConnection(const ServerConnection&) = delete;

                /// <summary></summary>
                ServerConnection& operator=(const ServerConnection&) = delete;

                /// <summary>Start the first asynchronous operation for the connection.</summary>
                void start() { read(); }
                /// <summary>Stop all asynchronous operations associated with the connection.</summary>
                void stop()
                {
                    try
                    {
                        if (m_socket.is_open()) {
                            m_socket.close();
                        }
                    }
                    catch(const std::exception&) { /* ignore */ }
                }

            private:
                /// <summary>Perform an asynchronous read operation.</summary>
                void read()
                {
                    if (!m_persistent) {
                        auto self(this->shared_from_this());
                    }

                    m_socket.async_read_some(asio::buffer(m_buffer), [=](asio::error_code ec, std::size_t bytes_transferred) {
                        if (!ec) {
                            HTTPLexer::ResultType result;
                            char* content;

                            std::tie(result, content) = m_lexer.parse(m_request, m_buffer.data(), m_buffer.data() + bytes_transferred);

                            std::string contentLength = m_request.headers.find("Content-Length");
                            if (contentLength != "") {
                                size_t length = (size_t)::strtoul(contentLength.c_str(), NULL, 10);
                                m_request.content = std::string(content, length);
                            }

                            m_request.headers.add("RemoteHost", m_socket.remote_endpoint().address().to_string());

                            if (result == HTTPLexer::GOOD) {
                                m_requestHandler.handleRequest(m_request, m_reply);
                                write();
                            }
                            else if (result == HTTPLexer::BAD) {
                                m_reply = HTTPPayload::statusPayload(HTTPPayload::BAD_REQUEST);
                                write();
                            }
                            else {
                                read();
                            }
                        }
                        else if (ec != asio::error::operation_aborted) {
                            if (ec) {
                                ::LogError(LOG_REST, "%s, code = %u", ec.message().c_str(), ec.value());
                            }
                            m_connectionManager.stop(this->shared_from_this());
                        }
                    });
                }

                /// <summary>Perform an asynchronous write operation.</summary>
                void write()
                {
                    if (!m_persistent) {
                        auto self(this->shared_from_this());
                    } else {
                        m_reply.headers.add("Connection", "keep-alive");
                    }

                    auto buffers = m_reply.toBuffers();
                    asio::async_write(m_socket, buffers, [=](asio::error_code ec, std::size_t) {
                        if (m_persistent) {
                            m_lexer.reset();
                            m_reply.headers = HTTPHeaders();
                            m_reply.status = HTTPPayload::OK;
                            m_reply.content = "";
                            m_request = HTTPPayload();
                            read();
                        }
                        else {
                            if (!ec) {
                                try
                                {
                                    // initiate graceful connection closure
                                    asio::error_code ignored_ec;
                                    m_socket.shutdown(asio::ip::tcp::socket::shutdown_both, ignored_ec);
                                }
                                catch(const std::exception& e) { ::LogError(LOG_REST, "%s", ec.message().c_str()); }
                            }

                            if (ec != asio::error::operation_aborted) {
                                if (ec) {
                                    ::LogError(LOG_REST, "%s, code = %u", ec.message().c_str(), ec.value());
                                }
                                m_connectionManager.stop(this->shared_from_this());
                            }
                        }
                    });
                }

                asio::ip::tcp::socket m_socket;

                ConnectionManagerType& m_connectionManager;
                RequestHandlerType& m_requestHandler;

                std::array<char, 8192> m_buffer;

                HTTPPayload m_request;
                HTTPLexer m_lexer;
                HTTPPayload m_reply;

                bool m_persistent;
            };
        } // namespace http
    } // namespace rest
} // namespace network

#endif // __REST_HTTP__SERVER_CONNECTION_H__
