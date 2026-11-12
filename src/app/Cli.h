// WireScope - Command Line Interface Processor
#pragma once
#include <string>
#include <vector>

namespace WS::Cli {

int Run(int argc, wchar_t* argv[]);
void PrintHelp();

} // namespace WS::Cli
