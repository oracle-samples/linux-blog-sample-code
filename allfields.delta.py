#!/usr/bin/python

# allfields.delta.py
#
# Copyright (c)  2019 Oracle and/or its affiliates. All rights reserved.
# Licensed under the Universal Permissive License v 1.0 as shown at
# http://oss.oracle.com/licenses/upl.

# import modules and methods
import sys
import os
import argparse
from string import replace

# global variables
method_list = []
perf_counts = dict()

def parse_input_parameters():
# parse input parameters using argparse: 
#    -- before-file is the name of file with before post processed allfields only from perf report (with children)
#    -- after-file is the name of file with after post processed allfields only from perf report (with children)
    parser = argparse.ArgumentParser(description='allfields.delta.py -- calculate and print delta between two perf report outputs')
    parser.add_argument("-b", "--before-file", help="before perf report file name", type=str, default='before.allfields')
    parser.add_argument("-a", "--after-file",  help="after perf report file name", type=str, default='after.allfields')
    parser.add_argument("-d", "--delta-type",  help="type of delta (children, self or samples)", type=str, default='children')
    parser.add_argument("-v", "--verbosity",   help="verbosity level", type=int, choices=[0, 1], default=1)
    args = parser.parse_args()

    # echo input parameters
    if args.verbosity >= 1:
        print "parse_input_parameters: before file  == %s" % (args.before_file)
        print "parse_input_parameters: after  file  == %s" % (args.after_file)
        print "parse_input_parameters: delta  type  == %s" % (args.delta_type)
        print ""

    return args.before_file, args.after_file, args.delta_type, args.verbosity
# end parse_input_parameters

# read in allfields post processed perf report file, save results
# NOTE: please check output that perf report output format matches the sample below, else adjust parsing
# format with children (perf report -i FILE -n) is:
# Children      Self       Samples  Command          Shared Object                                     Symbol                  
# ........  ........  ............  ...............  ................................................  ........................
#
#   97.36%     0.00%             0  rds-stress       rds-stress                                        [.] main
def read_allfields_file( file_name, index, print_level ):
    
    with open(file_name) as fp:
        for line in fp:
            words = line.split()
            children = float(replace(words[0], "%", ""))
            self     = float(replace(words[1], "%", ""))
            samples  = int(words[2])
            command  = words[3]
            symbol   = words[6] 
            result_tuple = (children, self, samples)
           
            func_tuple = (command, symbol)
            if func_tuple not in method_list:
               method_list.append(func_tuple)
            perf_counts[func_tuple, index] = result_tuple
            
            if print_level >= 1:
               print "file_name    == %s index = %d" % (file_name, index)
               print "func_tuple   == (%s, %s)" % (command, symbol)
               print "result_tuple == (%5.2f, %5.2f, %d)" % (children, self, samples)

# end read_allfields_file

# print out deltas, calculating along the way
def print_deltas( before_file_name, after_file_name, delta_type, print_level ):

    print "perf report allfields delta report"
    print "   before file name == %s" % (before_file_name)
    print "   after  file name == %s" % (after_file_name)
    print "   delta  type      == %s" % (delta_type)
    print ""

    if delta_type == "children":
        delta_index = 0
    elif delta_type == "self":
        delta_index = 1
    elif delta_type == "samples":
        delta_index = 2
    else:
        print "Invalid delta type -- EXITING"
        return

    # NOTE: may wish to move command and symbol to end of line as some symbols can be quite long
    # NOTE: this is also the place to demangle if some of the symbols are from C++ code
    print "Command              Symbol                         Before#  After#   Delta  "
    print "-------------------- ------------------------------ -------  -------  -------"
    header = "         "
    for func_tuple in method_list:
        before = 0
        if (func_tuple, 0) in perf_counts.keys():
            before_tuple = perf_counts[func_tuple, 0]
            before       = before_tuple[delta_index]
        after = 0
        if (func_tuple, 1) in perf_counts.keys():
            after_tuple = perf_counts[func_tuple, 1]
            after       = after_tuple[delta_index]
        delta  = after - before
        if delta_index < 2:
            print "%-20s %-30s %7.2f  %7.2f  %7.2f" % (func_tuple[0], func_tuple[1], before, after, delta)
        else: 
            print "%-20s %-30s %7d  %7d  %7d" % (func_tuple[0], func_tuple[1], before, after, delta)

# end print_deltas

# Main Method:

# parse input parameters
before_file_name, after_file_name, delta_type, global_print_level = parse_input_parameters()

if not os.path.isfile(before_file_name):
   print "File name " + before_file_name + " does not exist. Exiting..."
   sys.exit()

if not os.path.isfile(after_file_name):
   print "File name " + after_file_name + " does not exist. Exiting..."
   sys.exit()

# read in the two input files
read_allfields_file(before_file_name, 0, global_print_level)
read_allfields_file(after_file_name,  1, global_print_level)

# print out the results
print_deltas(before_file_name, after_file_name, delta_type, global_print_level)

sys.exit()
