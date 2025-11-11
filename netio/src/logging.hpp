/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * SPDX-FileCopyrightText: Hsia-Jun(Randy) Li
 */

#pragma once

#include <memory>
#include <spdlog/sinks/null_sink.h>
#include <spdlog/spdlog.h>

namespace celaratcp {
namespace netio {
namespace logging {

#ifdef LOGGER_USE_SPDLOG
static constexpr std::string logger_name = PSOCKET_LOGGER_NAME;

inline std::shared_ptr<spdlog::logger> &
get_logger_internal()
{
  static std::shared_ptr<spdlog::logger> logger = spdlog::get(logger_name);

  if (!logger) {
    logger = spdlog::create<spdlog::sinks::null_sink_mt>(logger_name);
  }
  return logger;
}

template <typename... Args>
inline void
trace(spdlog::format_string_t<Args...> fmt, Args &&...args)
{
  get_logger_internal()->trace(fmt, std::forward<Args>(args)...);
}

template <typename... Args>
inline void
info(spdlog::format_string_t<Args...> fmt, Args &&...args)
{
  get_logger_internal()->info(fmt, std::forward<Args>(args)...);
}

template <typename... Args>
inline void
warn(spdlog::format_string_t<Args...> fmt, Args &&...args)
{
  get_logger_internal()->warn(fmt, std::forward<Args>(args)...);
}

template <typename... Args>
inline void
error(spdlog::format_string_t<Args...> fmt, Args &&...args)
{
  get_logger_internal()->error(fmt, std::forward<Args>(args)...);
}

#else
template <typename... Args>
inline void
trace(Args &&...)
{
}
template <typename... Args>
inline void
info(Args &&...)
{
}
template <typename... Args>
inline void
warn(Args &&...)
{
}
template <typename... Args>
inline void
error(Args &&...)
{
}
#endif

} // namespace logging

} // namespace netio

} // namespace celaratcp
