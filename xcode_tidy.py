#!/usr/bin/env python

# This file attempts to emulate the Clang Static Analyzer (as Xcode understands it) with respect
# to inputs and outputs. Instead of invoking the analyzer, however, this file will invoke 
# clang-tidy on the file given from Xcode with the `--analyze` flag. Other arguments to 
# clang-tidy are derived from the arguments given by Xcode.

# To run this file as if it were a static analyzer, modify this file:
# /Path/To/Xcode.app/Contents/PlugIns/Xcode3Core.ideplugin/Contents/SharedSupport/Developer/Library/Xcode/Plug-ins/Clang LLVM 1.0.xcplugin/Contents/Resources/Clang LLVM 1.0.xcspec
# in one location. Find the line:
# ExecPath = "$(CLANG_ANALYZER_EXEC)";
# and replace it with
# ExecPath = "/Path/To/this_file.py";

# Builtin
import sys
import json
import re
import subprocess
import fnmatch
import tempfile

# See requirements.txt
import yaml

# Don't forget about the symlink at  /Applications/Xcode_11/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib/clang/9.0.0/include!!!

CLANG_TIDY_DIR = "/Applications/Xcode_11/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin"
CLANG_TIDY_PATH = "{}/clang-tidy".format(CLANG_TIDY_DIR)

###
# Utilities
# =================================================================================================
# General purpose utilities that have no dependency on clang-tidy.
###

def find_if(sequence, predicate):
    return next((x for x in sequence if predicate(x)), None)

def sorted_unique_list(generator):
    return sorted(list(set(generator)))

###
# Args and Clang Tidy Config
# =================================================================================================
# The args object represents a dictionary of the arguments given to us by Xcode.
# The "tidy config" is a dictionary representation of clang-tidy --dump-config.
###

class args:
    def __init__(self, argv):
        self.list = list(args.generator(argv[1:]))

    # For flags `likeThis=100`, return `100`.
    # For flags `-likeThis`, return `-likeThis`.
    # For flags with parameters `-like this`, return `this`
    # Returns first found instance.
    def __getitem__(self, flag):
        found = find_if(self.list, lambda x: x[0].startswith(flag))
        if not found: return None
        return found[0][found.index('=') + 1:] if '=' in found[0] else found[-1]

    # Return our list of arg lists concatenated together
    def as_flat_list(self):
        return [parameter for arg in self.list for parameter in arg]
    
    # Return our list of arg lists concatenated together, removing
    # arguments that are intended for the clang static analyzer, and
    # should not be passed to clang-tidy's clang invocation.
    def as_pruned_flat_list(self):
        return [parameter for arg in self.list for parameter in arg if not args.should_be_pruned(arg)]
    
    @staticmethod
    # Prune out arguments that are intended for an actual analyzer context.
    def should_be_pruned(arg):
        return any([arg[0].startswith(k) for k in [
            '-Xclang', '-D__clang_analyzer__', '--analyze',
            '-fmodules', '-gmodules',
        ]])

    @staticmethod
    def is_flag(arg):
        return arg[0] == '-'

    @staticmethod
    def takes_flag_as_parameter(arg):
        return arg == '-Xclang'

    @staticmethod
    def generator(argv):
        if not argv: return
        if not args.is_flag(argv[0]):
            raise RuntimeError("Argument list starts without a flag.")

        acc = [argv[0]]
        for arg in argv[1:]:
            if args.is_flag(arg) and not args.takes_flag_as_parameter(acc[-1]):
                yield acc
                acc = [arg]
            else:
                acc.append(arg)

        yield acc

def get_tidy_config():
    command = [CLANG_TIDY_PATH, "--dump-config"]
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = process.communicate()
    try:
        return yaml.safe_load(out)
    except yaml.YAMLError as exc:
        return None

XCODE_SELECT_PATH = None
def xcode_select_path():
    global XCODE_SELECT_PATH
    if not XCODE_SELECT_PATH:
        XCODE_SELECT_PATH = subprocess.check_output(["xcode-select", "-p"]).strip()
    return XCODE_SELECT_PATH

###
# The Dependencies File 
# =================================================================================================
# Create a file that indicates to Xcode what file changes constitute a re-analysis. 
# We only include the analyzed translation unit, and included headers thereof that match the 
# clang-tidy configuration's filter regex.
# Assuming you're analyzing a file named main.cpp that includes foo.hpp and bar.hpp, 
# this makes a file at:
# Intermediates.noindex/tidyable.build/Debug/tidyable.build/StaticAnalyzer/tidyable/tidyable/normal/x86_64/main.d
# with the contents:
# dependencies: /Absolute/Path/To/main.cpp /Absolute/Path/To/First/foo.hpp /Absolute/Path/To/Second/bar.hpp
###

def traced_include_to_path(traced):
    if traced and traced[0] == '.':
        return traced[traced.find('/') : ]

def derive_dependencies(clangOutput, translationUnit, headerFilterRegexString):
    result = [translationUnit]
    for line in clangOutput.split('\n'):
        path = traced_include_to_path(line)
        if path and fnmatch.fnmatch(path, headerFilterRegexString):
            result.append(path)
    return result

def make_dependencies_file(args, dependentFiles):
    with open(args["-MF"], 'w+') as f:
        f.write("{0}: ".format(args["-MT"]))
        for dep in dependentFiles:
            f.write("{} ".format(dep))

###
# Invoking Clang Tidy 
# =================================================================================================
###

# For reasons that remain unclear to me, the Apple Clang distribution has no issue compiling the following program:
# 
# #include <xmmintrin.h>
# int main() {}
# 
# Yet, clang-tidy errors-out on two missing symbols (stubbed below). The goal is to only define these identifiers
# executing analyers that will not generate machine code that is executed.
# 
# Work remains to identify why Apple Clang differs from clang-tidy, and if clang 9.0 exhibits the same behavior.
# 
# These are indeed GCC builtins:
#     https://gcc.gnu.org/onlinedocs/gcc-4.2.3/gcc/X86-Built_002din-Functions.html
# And clang claims to support all GCC builtins.
#     https://releases.llvm.org/3.1/tools/clang/docs/LanguageExtensions.html#builtins
#
# Here, we define those builtins to be macros that abort ungracefully.
def clang_builtin_workaround_flags():
    return ["-D__builtin_ia32_storehps(...)=__builtin_trap()",
            "-D__builtin_ia32_storelps(...)=__builtin_trap()"]

# Arguments to be passed to the clang compiler behind clang-tidy.
# AKA the args after "--" in the clang-tidy invocation.
def get_clang_arguments(args):
    result = []
    xcode_path = xcode_select_path()

    # result.append("-isystem{}/Toolchains/XcodeDefault.xctoolchain/usr/lib/clang/11.0.0/include".format(xcode_path))
    # result.append("-isystem{}/Toolchains/XcodeDefault.xctoolchain/usr/include".format(xcode_path))
    # result.append("-isystem{}/Toolchains/XcodeDefault.xctoolchain/usr/include/c++/v1".format(xcode_path))

    # result.append("-isystem{}/Toolchains/XcodeDefault.xctoolchain/usr/include/c++/v1".format(xcode_path))
    # result.append("-isystem{}/Toolchains/XcodeDefault.xctoolchain/usr/lib/clang/11.0.0/include".format(xcode_path))

    result.append("-isystem{}/Toolchains/XcodeDefault.xctoolchain/usr/include".format(xcode_path))
    # if args.wants_workaround:
    result.extend(clang_builtin_workaround_flags())
    result.extend(args.as_pruned_flat_list())

    # /Applications/Xcode_11/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib/clang/11.0.0/include 
    # /Applications/Xcode_11/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/include   
    return result        

def invoke_clang_tidy(args):
    command = [CLANG_TIDY_PATH, args["--analyze"]]
    command += ["--"]
    command += get_clang_arguments(args)
    command += ["-v"]
    print ' '.join(command)
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = process.communicate()
    return (process.returncode, out, err)

###
# The Diagnostic File =============================================================================
# Xcode's support for the Clang Static Analyzer works by parsing a .plist (XML) file that's placed
# by the analyzer at a path in the DerivedData folder. That path is specified by the `-o` argument
# given to the analyzer. We parse the results of clang-tidy into that format, and place the file
# at the expected directory, which makes Xcode report the clang-tidy warnings as if they were 
# static analyzer warnings. At this time, we do not make use of the "path" feature supported by
# this format, which allows in-editor tracing of the path of execution that led to the diagnostic.
###

# The proper way to do this should be a clang-tidy argument to output as a analyzer-friendly
# plist. But that may have to be post-MVP. For now, we use the fact that warnings take the form:
# /Path/To/file.cpp:<Line>:<Column> <Category>: <Note> [<Diagnostic Type>]
class CAPTURE_GROUP():
    FILE_PATH = 0       # Absolute file path.
    LINE = 1            # Line where diagnostic occurred
    COLUMN = 2          # column where diagnostic ocurred
    LEVEL = 3           # warning, info, error, etc
    DESCRIPTION = 4     # description of diagnostic
    CHECK_NAME = 5      # Check name [llvm.exampleCheck.foo]

TIDY_WARNING_REGEX = re.compile("((?:\/.*){3,}):([0-9]+):([0-9]+):\s*(.*):\s*(.*)\s*(\[.*\])")
# This makes the check name optional. Unclear if needed yet.
# TIDY_WARNING_REGEX = re.compile("((?:\/.*){3,}):([0-9]+):([0-9]+):\s*(.*):\s*(.*)(\s*\[.*\]){0,1}")

def make_diagnostic(match, fileIndex):
    return {
        "check_name" : match[CAPTURE_GROUP.CHECK_NAME],
        "location" : {
            "col" : match[CAPTURE_GROUP.COLUMN],
            "file" : fileIndex,
            "line" : match[CAPTURE_GROUP.LINE]
        },
        # Consider omitting the CHECK_NAME by command line arg.
        "description" :"{0} {1}".format(match[CAPTURE_GROUP.DESCRIPTION], match[CAPTURE_GROUP.CHECK_NAME])
    }

def make_diagnostics(matches, affectedFiles):
    return [make_diagnostic(m, affectedFiles.index(m[CAPTURE_GROUP.FILE_PATH])) for m in matches]

def parse_clang_tidy_output(output):
    matches = re.findall(TIDY_WARNING_REGEX, output)
    affectedFiles = sorted_unique_list( m[CAPTURE_GROUP.FILE_PATH] for m in matches )
    return json.dumps({
        "files" : affectedFiles,
        "diagnostics" : make_diagnostics(matches, affectedFiles)
    })

def make_output_plist(path, output):
    # Write a temp file out as json, then use plutil to convert to an apple-friendly plist file.
    with tempfile.NamedTemporaryFile(mode="w+") as tmp:
        json = parse_clang_tidy_output(output)
        tmp.writelines(json)
        tmp.seek(0)

        command = ["plutil", "-convert", "xml1", tmp.name, "-o", path]
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = process.communicate()

###
# Main 
# ============================================================================================
###

if __name__ == "__main__":
    args = args(sys.argv)
    config = get_tidy_config()

    retcode, output, error = invoke_clang_tidy(args)

    # When we pass --trace-includes to clang, the result seems to go to stderr of clang-tidy.
    dependentFiles = derive_dependencies(error, args["--analyze"], config['HeaderFilterRegex']) 
    make_dependencies_file(args, dependentFiles)

    if output:
        make_output_plist(args["-o"], output)

    if error:
        print "ERR\n{}".format(error)

    sys.exit(retcode)