#
# This script will allow a user to use a /proc/kallsyms output file to import symbols into IDA for Android kernels.
#

from idautils import *
from idaapi import *
import time

ADDRESS = 0
TYPE = 1
NAME = 2

# Prompt the user for the kallsyms output file and open it
filePath = idaapi.ask_file(0, 'kallsyms.txt|*.txt|All files (*.*)|*.*', 'Select a file containing kallsyms output')
file = open(filePath, 'r')
syms = file.readlines()

functionTable = {}
dataTable = {}
kernelBase = '0'

# This script can take quite a while to run - we should warn the user that IDA might be sluggish for a while.
idaapi.warning('Note that after the script finishes, IDA will re-run it\'s analyzer on the ELF. Give it about 5 minutes.')

# convertAddressToSlide takes a given address and converts it to a slide based on the kernel base parsed
# from _text.
def convertAddressToSlide(addr):
	return int(addr, 16) - int(kernelBase, 16)

startTime = time.clock()

# Iterate through each symbol
for sym in syms:
	# Symbol entries follow the following format 
	sym = sym.replace('\n', '')
	symbol = sym.split(' ')

	symAddress = symbol[ADDRESS]
	symName = symbol[NAME]
	symSlide = convertAddressToSlide(symAddress)

	# Ignore _head because it's not a function or global
	if symbol[NAME] == '_head':
		continue

	# IDA does not allow names with a "byte_" prefix, and a few entries do have these names, so we'll
	# make special exceptions and not port these names.
	if symbol[NAME][0:5] == 'byte_':
		continue

	# The kernel base can be found via the _text symbol
	if symbol[TYPE] == 'T' and symbol[NAME] == '_text':
		kernelBase = symbol[ADDRESS]
		print 'Found kernel base @ 0x' + symbol[ADDRESS]

	#
	# We're going to construct look-up tables for functions and data. The reason we're doing this instead
	# of just labelling here and now is some addresses have more than one symbol entry, and in the future
	# we may want to add a comment denoting the other names the entity goes by.
	#

	# Parse function entries
	if symbol[TYPE].lower() == 't':
		# Create a list if a list does not already exist for this address
		if symSlide not in functionTable:
			functionTable[symSlide] = []

		# Add name(s) to the address entry in the function table
		functionTable[symSlide].append(symName)

	# Parse data entries
	elif symbol[TYPE].lower() == 'd':
		# Create a list if a list does not already exist for this address
		if symSlide not in dataTable:
			dataTable[symSlide] = []

		# Add name(s) to the address entry in the data table
		dataTable[symSlide].append(symName)


for vaddr, funcNames in functionTable.items():
	# Mark virtual address as code, and create a function
	idaapi.auto_make_proc(vaddr)

	# Label in IDA
	idaapi.set_name(vaddr, funcNames[0])

for vaddr, dataNames in dataTable.items():
	# Label in IDA
	idaapi.set_name(vaddr, dataNames[0])

endTime = time.clock()

print 'Finished in ' + str(endTime - startTime) + ' seconds.'
