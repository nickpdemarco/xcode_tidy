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

# The proper way to do this should be an option to clang-tidy to output as a analyzer-friendly
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

FLAGS_WITH_SPACE_SPARATED_ARGUMENTS = [ # TODO This is likely an incomplete list 
    "-x",
    "-target",
    "-isysroot",
    "-iquote",
    "-MT",
    "-MF",
    "--analyze",
    "-o",
]

###
# Args and Utilities 
# =================================================================================================
# The args object represents a dictionary of the arguments given to us by Xcode.
# The "tidy config" is a dictionary representation of clang-tidy --dump-config.
###

class args:
    def __getitem__(self, key):
        try:
            return getattr(self, key)
        except:
            return None

    def __iter__(self):
        return vars(self).iteritems()

def make_args(argv):
    result = args()

    N = len(argv)
    i = 0
    while i < N:
        arg = argv[i]
        if arg in FLAGS_WITH_SPACE_SPARATED_ARGUMENTS:
            setattr(result, arg, argv[i + 1])
            i += 2
        elif '=' in arg:
            spl = arg.split('=')
            setattr(result, spl[0], spl[1])
            i += 1
        else:
            setattr(result, arg, True)
            i += 1
    
    return result

def get_tidy_config():
    command = ["/Users/demarco/clang-tidy", "--dump-config"]
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

def find_if(sequence, predicate):
    return next((x for x in sequence if predicate(x)), None)

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

# Arguments to be passed to the clang compiler behind clang-tidy.
# AKA the args after "--" in the clang-tidy invocation. All header search paths for now.
def get_clang_arguments(args):

    result = ["-isysroot", args["-isysroot"], "--trace-includes"]

    xcode_path = xcode_select_path()
    # Why do I need to do these next two? Does xcode really include search paths not listed in the compile command?
    result.append( "-I{}/Toolchains/XcodeDefault.xctoolchain/usr/include/c++/v1/".format(xcode_path))
    # This feels fragile. Derive path from xcode version number?
    result.append( "-I{}/Toolchains/XcodeDefault.xctoolchain/usr/lib/clang/11.0.0/include/".format(xcode_path))

    for flag, value in args:
        if flag.startswith("-I"):
            result.append(flag)

    return result        

def invoke_clang_tidy(args):
    command = ["/Users/demarco/clang-tidy", args["--analyze"]]
    command += ["--"]
    command += get_clang_arguments(args)
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
    affectedFiles = sorted(list( { m[CAPTURE_GROUP.FILE_PATH] for m in matches } )) # Sorted, unique list.
    json_dict = {
        "files" : affectedFiles,
        "diagnostics" : make_diagnostics(matches, affectedFiles)
    }
    return json.dumps(json_dict)

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
# Main ============================================================================================
###

if __name__ == "__main__":
    args = make_args(sys.argv)
    config = get_tidy_config()
    retcode, output, error = invoke_clang_tidy(args)

    # When we pass --trace-includes to clang, the result seems to go to stderr of clang-tidy.
    dependentFiles = derive_dependencies(error, args["--analyze"], config['HeaderFilterRegex']) 
    make_dependencies_file(args, dependentFiles)

    if output:
        make_output_plist(args["-o"], output)

    sys.exit(retcode)