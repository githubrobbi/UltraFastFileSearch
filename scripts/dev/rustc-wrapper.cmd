@echo off
:: SPDX-License-Identifier: MPL-2.0
:: Copyright (c) 2025-2026 SKY, LLC.
::
:: Optional-sccache rustc wrapper (Windows twin of the POSIX
:: `rustc-wrapper` shim in this directory).
::
:: Cargo invokes a `build.rustc-wrapper` as `<wrapper> <rustc> <args...>`.
:: This shim forwards to sccache when it is on PATH and runs rustc
:: directly when it is not, so a missing sccache degrades to an uncached
:: build instead of failing every cargo invocation with
:: "could not execute process `sccache ... rustc -vV`" (issue #587).
::
:: `%*` carries cargo's own quoting through untouched; `exit /b`
:: propagates rustc's exit code, which cargo relies on to detect
:: compilation failure.

where sccache >nul 2>nul
if %ERRORLEVEL% equ 0 (
    sccache %*
    exit /b %ERRORLEVEL%
)

%*
exit /b %ERRORLEVEL%
