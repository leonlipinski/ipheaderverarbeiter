#!/usr/bin/env python3
from tkinter import *
from tkinter import ttk



def decimalToBinary(number):
	return str(int(bin(int(number))[2:]))


def binaryToDecimal(number):
	return str(int(str(number), 2))


def hexToBinary(number):
	return bin(int(str(number), 16))[2:]


def binaryToHex(number):
	return hex(int(str(number), 2))[2:]


def binaryToIPv4(octets):
	decimals = []
	octets_splited = octets.split(".")
	for p in octets_splited:
		decimals.append(str(binaryToDecimal(p)))
	return ".".join(decimals)


def ipv4ToBinary(ip_address):
	octets = []
	ip_splited = ip_address.split(".")
	for p in ip_splited:
		if int(p) in list(range(0, 256)):
			octets.append(str(decimalToBinary(p)).zfill(8))
		else:
			print("octet not valid")
	return ".".join(octets)


def binaryToIPv6(octets):
	decimals = []
	octets_splited = octets.split(":")
	for p in octets_splited:
		decimals.append(str(binaryToHex(p)).zfill(4))
	return ":".join(decimals)

def ipv6ToBinary(ip_address):
	octets = []
	ip_splited = ip_address.split(":")
	for p in ip_splited:
		if int(p, 16) in list(range(0xffff)):
			octets.append(str(hexToBinary(p)))
		else:
			print("octet not valid")

	return ":".join(octets)




def binary_filter(bit_list):
	non_binary_numbers = []
	for num in bit_list:
		if num is '0' or num is '1':
			pass
		else:
			non_binary_numbers.append(num)
	return non_binary_numbers

ipv4 = {}
ipv4["version"] = 4
ipv4["ihl"] = 4
ipv4["tos"] = 8
ipv4["length"] = 16
ipv4["identifiction"] = 16
ipv4["flags"] = 3
ipv4["fragmentoffset"] = 13
ipv4["ttl"] = 8
ipv4["protocol"] = 8
ipv4["hdrcheck"] = 16
ipv4["srcaddr"] = 32
ipv4["destaddr"] = 32

ipv6 = {}
ipv6["version"] = 4
ipv6["trafficclass"] = 8
ipv6["flowlabel"] = 20
ipv6["payloadlength"] = 16
ipv6["nextheader"] = 8
ipv6["hoplimit"] = 8
ipv6["srcaddr"] = 128
ipv6["destaddr"] = 128

def analize(string):
	dictionary = { }
	dictionary['Current'] = string
	analizer_list = string.split('-')

	if len(analizer_list) is 12:
		dictionary['Version'] = 4
		splited = analizer_list[-1].replace(".", "")
	elif len(analizer_list) is 8:
		dictionary['Version'] = 6
		splited = analizer_list[-1].replace(":", "")
	else:
		dictionary['Version'] = 'Unknown'

	# print(analizer_list[-1])
	if len(binary_filter(list(splited))) is 0:
		dictionary['number_system'] = 'Binary'
	else:
		if dictionary['Version'] is 4:
			dictionary['number_system'] = 'Decimal'
		elif dictionary['Version'] is 6:
			dictionary['number_system'] = 'Hexadecimal'

	converted = []

	if dictionary['number_system'] is 'Binary':
		header = analizer_list[:-2]
		if dictionary['Version'] is 4:
			new_header = list(map(binaryToDecimal, header))
			new_header.append(binaryToIPv4(analizer_list[-2]))
			new_header.append(binaryToIPv4(analizer_list[-1]))

		elif dictionary['Version'] is 6:
			new_header = list(map(binaryToHex, header))
			new_header.append(binaryToIPv6(analizer_list[-2]))
			new_header.append(binaryToIPv6(analizer_list[-1]))

	elif dictionary['number_system'] is 'Decimal':
		# Decimal to Binary

		header = analizer_list[:-2]
		new_header = []
		dict_keys = list(ipv4.keys())
		for num, x in enumerate(header):
			new_header.append(str(decimalToBinary(x)).zfill(ipv4[dict_keys[num]]))
		new_header.append(ipv4ToBinary(analizer_list[-2]))
		new_header.append(ipv4ToBinary(analizer_list[-1]))

	elif dictionary['number_system'] is 'Hexadecimal':
		# Hexadecimal to Binary
		header = analizer_list[:-2]
		new_header = []
		dict_keys = list(ipv6.keys())
		for num, x in enumerate(header):
			new_header.append(str(decimalToBinary(x)).zfill(ipv6[dict_keys[num]]))
		new_header.append(ipv6ToBinary(analizer_list[-2]))
		new_header.append(ipv6ToBinary(analizer_list[-1]))
	return '-'.join(new_header)

class header_ipv4:

	def __init__(self):

		self.version = ''
		self.version_title = 'version'
		self.version_default = 4

		self.ihl = ''
		self.ihl_title = 'ihl'
		self.ihl_default = 6

		self.tos = ''
		self.tos_title = 'tos'
		self.tos_default = 24

		self.length = ''
		self.length_title = 'length'
		self.length_default = 6

		self.identifiction = ''
		self.identifiction_title = 'identifiction'
		self.identifiction_default = 0

		self.flags = ''
		self.flags_title = 'flags'
		self.flags_default = '000'

		self.fragmentoffset = ''
		self.fragmentoffset_title = 'fragmentoffset'
		self.fragmentoffset_default = 0

		self.ttl = ''
		self.ttl_title = 'ttl'
		self.ttl_default = 32

		self.protocol = ''
		self.protocol_title = 'protocol'
		self.protocol_default = 0

		self.hdrcheck = ''
		self.hdrcheck_title = 'hdrcheck'
		self.hdrcheck_default = 0

		self.srcaddr = ''
		self.srcaddr_title = 'srcaddr'
		self.srcaddr_default = "195.168.1.102"

		self.destaddr = ''
		self.destaddr_title = 'destaddr'
		self.destaddr_default = "223.168.1.102"


	def __str__(self):
		return "{version}-{ihl}-{tos}-{length}-{identifiction}-{flags}-{fragmentoffset}-{ttl}-{protocol}-{hdrcheck}-{srcaddr}-{destaddr}".format(

				version = str(self.version),
				ihl = str(self.ihl),
				tos = str(self.tos),
				length = str(self.length),
				identifiction = str(self.identifiction),
				flags = str(self.flags),
				fragmentoffset = str(self.fragmentoffset),
				ttl = str(self.ttl),
				protocol = str(self.protocol),
				hdrcheck = str(self.hdrcheck),
				srcaddr = str(self.srcaddr),
				destaddr = str(self.destaddr))


	def change_to_default(self):
		if self.version is '':
			self.version = self.version_default
		if self.ihl is '':
			self.ihl = self.ihl_default
		if self.tos is '':
			self.tos = self.tos_default
		if self.length is '':
			self.length = self.length_default
		if self.identifiction is '':
			self.identifiction = self.identifiction_default
		if self.flags is '':
			self.flags = self.flags_default
		if self.fragmentoffset is '':
			self.fragmentoffset = self.fragmentoffset_default
		if self.ttl is '':
			self.ttl = self.ttl_default
		if self.protocol is '':
			self.protocol = self.protocol_default
		if self.hdrcheck is '':
			self.hdrcheck = self.hdrcheck_default
		if self.srcaddr is '':
			self.srcaddr = self.srcaddr_default
		if self.destaddr is '':
			self.destaddr = self.destaddr_default

class header_ipv6:

	def __init__(self):
		self.version = ''
		self.version_title = 'version'
		self.version_default = 6

		self.traffic_class = ''
		self.traffic_class_title = 'trafficclass'
		self.traffic_class_default = 24

		self.flow_label = ''
		self.flow_label_title = 'flowlabel'
		self.flow_label_default = 10

		self.payload_length = ''
		self.payload_length_title = 'payloadlength'
		self.payload_length_default = 0

		self.next_header = ''
		self.next_header_title = 'nextheader'
		self.next_header_default = 0

		self.hop_limit = ''
		self.hop_limit_title = 'hoplimit'
		self.hop_limit_default = 32

		self.source_address = ''
		self.source_address_title = 'srcaddr'
		self.source_address_default = '0db8:0000:08d3:0000:8a2e:0070:7344'

		self.destination_address = ''
		self.destination_address_title = 'destaddr'
		self.destination_address_default = '2001:0db8:85a3:08d3:1319:8a2e:0370:7344'


	def __str__(self):
		return "{version}-{trafficclass}-{flowlabel}-{payloadlength}-{nextheader}-{hoplimit}-{srcaddr}-{destaddr}".format(

				version = str(self.version),
				trafficclass = str(self.traffic_class),
				flowlabel = str(self.flow_label),
				payloadlength = str(self.payload_length),
				nextheader = str(self.next_header),
				hoplimit = str(self.hop_limit),
				srcaddr = str(self.source_address),
				destaddr = str(self.destination_address))

	def change_to_default(self):
		if self.version is '':
			self.version = self.version_default
		if self.traffic_class is '':
			self.traffic_class = self.traffic_class_default
		if self.flow_label is '':
			self.flow_label = self.flow_label_default
		if self.payload_length is '':
			self.payload_length = self.payload_length_default
		if self.next_header is '':
			self.next_header = self.next_header_default
		if self.hop_limit is '':
			self.hop_limit = self.hop_limit_default
		if self.source_address is '':
			self.source_address = self.source_address_default
		if self.destination_address is '':
			self.destination_address = self.destination_address_default


class GUI:


	def __init__(self, master):

		notebook = ttk.Notebook(master)
		notebook.grid()
		notebook.grid_rowconfigure(0, weight = 1)
		notebook.grid_columnconfigure(0, weight = 1)

		frame1 = ttk.Frame(notebook)
		frame1.grid_rowconfigure(0, weight = 1)
		frame1.grid_columnconfigure(0, weight = 1)

		frame2 = ttk.Frame(notebook)
		frame2.grid_rowconfigure(0, weight = 1)
		frame2.grid_columnconfigure(0, weight = 1)

		notebook.add(frame1, text = 'IP Header Version 4')
		notebook.add(frame2, text = 'IP Header Version 6')



		headerv4 = header_ipv4()
		headerv4.change_to_default()

		self.ipv4(frame1, headerv4)

		headerv6 = header_ipv6()
		headerv6.change_to_default()

		self.ipv6(frame2, headerv6)


	def grid_tester(self, frame, g_column, g_row):
		gridtest = Frame(frame, bd = 3, relief = RIDGE)
		gridtest.grid(column = g_column, row = g_row, sticky = (W, E))
		Label(gridtest, text = 'GridTest{}-{}'.format(g_column, g_row)).grid(column = 0, row = 0)
		gridtest_string = StringVar()
		Entry(gridtest, textvariable = gridtest_string, bg = 'white').grid(column = 0, row = 1, sticky = (W, E))
		gridtest_string.set('')
		gridtest.grid()


	def ipv4(self, frame, header):


		version = Frame(frame, bd = 3, relief = RIDGE)

		version.grid(column = 0, row = 1, sticky = (E,W))
		version.grid_rowconfigure(0, weight = 1)
		version.grid_columnconfigure(0, weight = 1)
		Label(version, text = 'Version').pack(fill=BOTH)
		version_string = StringVar()
		Entry(version, textvariable = version_string, bg = 'white').pack(fill=BOTH)
		version_string.set(header.version)
		version.grid()

		ihl = Frame(frame, bd = 3, relief = RIDGE)
		ihl.grid(column = 1, row = 1, sticky = (E,W))
		ihl.grid_rowconfigure(0, weight = 1)
		ihl.grid_columnconfigure(0, weight = 1)
		Label(ihl, text = 'IHL').pack(fill=BOTH)
		ihl_string = StringVar()
		Entry(ihl, textvariable = ihl_string, bg = 'white').pack(fill=BOTH)
		ihl_string.set(header.ihl)
		ihl.grid()

		type_of_service = Frame(frame, bd = 3, relief = RIDGE)
		type_of_service.grid(column = 2, row = 1, columnspan = 2, sticky = (E,W))
		Label(type_of_service, text = 'Type of Service').pack(fill=BOTH)
		type_of_service_string = StringVar()
		Entry(type_of_service, textvariable = type_of_service_string, bg = 'white').pack(fill=BOTH)
		type_of_service_string.set(header.tos)
		type_of_service.grid()

		total_length = Frame(frame, bd = 3, relief = RIDGE)
		total_length.grid(column = 4, row = 1, columnspan = 12, sticky = (E,W))
		Label(total_length, text = 'Total Length').pack(fill=BOTH)
		total_length_string = StringVar()
		Entry(total_length, textvariable = total_length_string, bg = 'white').pack(fill=BOTH)
		total_length_string.set(header.length)
		total_length.grid()

		identifier = Frame(frame, bd = 3, relief = RIDGE)
		identifier.grid(column = 0, row = 2, columnspan = 4, sticky = (E,W))
		Label(identifier, text = 'Identifier').pack(fill=BOTH)
		identifier_string = StringVar()
		Entry(identifier, textvariable = identifier_string, bg = 'white').pack(fill=BOTH)
		identifier_string.set(header.identifiction)
		identifier.grid()

		flags = Frame(frame, bd = 3, relief = RIDGE)
		flags.grid(column = 4, row = 2, sticky = (E,W))
		Label(flags, text = 'Flags').pack(fill=BOTH)
		flags_string = StringVar()
		Entry(flags, textvariable = flags_string, bg = 'white').pack(fill=BOTH)
		flags_string.set(header.flags)
		flags.grid()

		fragmented_offset = Frame(frame, bd = 3, relief = RIDGE)
		fragmented_offset.grid(column = 5, row = 2, columnspan = 3, sticky = (E,W))
		Label(fragmented_offset, text = 'Fragmented Offset').pack(fill=BOTH)
		fragmented_offset_string = StringVar()
		Entry(fragmented_offset, textvariable = fragmented_offset_string, bg = 'white').pack(fill=BOTH)
		fragmented_offset_string.set(header.fragmentoffset)
		fragmented_offset.grid()

		time_to_live = Frame(frame, bd = 3, relief = RIDGE)
		time_to_live.grid(column = 0, row = 3, columnspan = 2, sticky = (E,W))
		Label(time_to_live, text = 'Time to Live').pack(fill=BOTH)
		time_to_live_string = StringVar()
		Entry(time_to_live, textvariable = time_to_live_string, bg = 'white').pack(fill=BOTH)
		time_to_live_string.set(header.ttl)
		time_to_live.grid()

		protocol = Frame(frame, bd = 3, relief = RIDGE)
		protocol.grid(column = 2, row = 3, columnspan = 2, sticky = (E,W))
		Label(protocol, text = 'Protocol').pack(fill=BOTH)
		protocol_string = StringVar()
		Entry(protocol, textvariable = protocol_string, bg = 'white').pack(fill=BOTH)
		protocol_string.set(header.protocol)
		protocol.grid()

		header_checksum = Frame(frame, bd = 3, relief = RIDGE)
		header_checksum.grid(column = 4, row = 3, columnspan = 4, sticky = (E,W))
		Label(header_checksum, text = 'Header Checksum').pack(fill=BOTH)
		header_checksum_string = StringVar()
		Entry(header_checksum, textvariable = header_checksum_string, bg = 'white').pack(fill=BOTH)
		header_checksum_string.set(header.hdrcheck)
		header_checksum.grid()

		source_ip_address = Frame(frame, bd = 3, relief = RIDGE)
		source_ip_address.grid(column = 0, row = 4, columnspan = 8, sticky = (E,W))
		Label(source_ip_address, text = 'Source IP Address').pack(fill=BOTH)
		source_ip_address_string = StringVar()
		Entry(source_ip_address, textvariable = source_ip_address_string, bg = 'white').pack(fill=BOTH)
		source_ip_address_string.set(header.srcaddr)
		source_ip_address.grid()

		destination_ip_address = Frame(frame, bd = 3, relief = RIDGE)
		destination_ip_address.grid(column = 0, row = 5, columnspan = 8, sticky = (E,W))
		Label(destination_ip_address, text = 'Destination IP Address').pack(fill=BOTH)
		destination_ip_address_string = StringVar()
		Entry(destination_ip_address, textvariable = destination_ip_address_string, bg = 'white').pack(fill=BOTH)
		destination_ip_address_string.set(header.destaddr)
		destination_ip_address.grid()

		decimal_string = Frame(frame, bd = 3, relief = RIDGE)
		decimal_string.grid(column = 0, row = 7, columnspan = 7, sticky = (E,W))
		Label(decimal_string, text = 'Decimal String').pack(fill=BOTH)
		decimal_string_string = StringVar()
		Entry(decimal_string, textvariable = decimal_string_string, bg = 'white').pack(fill=BOTH)
		decimal_string_string.set('')
		decimal_string.grid()

		binary_string = Frame(frame, bd = 3, relief = RIDGE)
		binary_string.grid(column = 0, row = 8, columnspan = 7, sticky = (E,W))
		Label(binary_string, text = 'Binary String').pack(fill=BOTH)
		binary_string_string = StringVar()
		Entry(binary_string, textvariable = binary_string_string, bg = 'white').pack(fill=BOTH)
		binary_string_string.set('')
		binary_string.grid()

		rerun_decimal_string = Frame(frame, bd = 3, relief = RIDGE)
		rerun_decimal_string.grid(column = 0, row = 9, columnspan = 7, sticky = (E,W))
		Label(rerun_decimal_string, text = 'ReRun Decimal String').pack(fill=BOTH)
		rerun_decimal_string_string = StringVar()
		Entry(rerun_decimal_string, textvariable = rerun_decimal_string_string, bg = 'white').pack(fill=BOTH)
		rerun_decimal_string_string.set('')
		rerun_decimal_string.grid()


		button1 = Button(frame, text = "Print", fg = "red",
						 command = lambda: decimal_string_string.set(
								 '-'.join([version_string.get(), ihl_string.get(), type_of_service_string.get(),
								  total_length_string.get(), identifier_string.get(), flags_string.get(),
								  fragmented_offset_string.get(), time_to_live_string.get(), protocol_string.get(),
								  header_checksum_string.get(), source_ip_address_string.get(),
								  destination_ip_address_string.get()])))
		button1.grid(column = 7, row = 7, sticky = (W, E))

		button2 = Button(frame, text = "Convert", fg = "red", command = lambda: binary_string_string.set(analize(decimal_string_string.get())))

		button2.grid(column = 7, row = 8, sticky = (W, E))

		button3 = Button(frame, text = "Convert", fg = "red", command = lambda: rerun_decimal_string_string.set(analize(binary_string_string.get())))

		button3.grid(column = 7, row = 9, sticky = (W, E))



	def ipv6(self, frame, header):

		version = Frame(frame, bd = 3, relief = RIDGE)
		version.grid(column = 0, row = 1, columnspan = 2,sticky = (W, E))
		Label(version, text = 'Version').pack(fill=BOTH)
		version_string = StringVar()
		Entry(version, textvariable = version_string, bg = 'white').pack(fill=BOTH)
		version_string.set(header.version)
		version.grid()

		traffic_class = Frame(frame, bd = 3, relief = RIDGE)
		traffic_class.grid(column = 2, row = 1, columnspan = 2,sticky = (W, E))
		Label(traffic_class, text = 'Traffic Class').pack(fill=BOTH)
		traffic_class_string = StringVar()
		Entry(traffic_class, textvariable = traffic_class_string, bg = 'white').pack(fill=BOTH)
		traffic_class_string.set(header.traffic_class)
		traffic_class.grid()

		flow_label = Frame(frame, bd = 3, relief = RIDGE)
		flow_label.grid(column = 4, row = 1, columnspan = 5,sticky = (W, E))
		Label(flow_label, text = 'Flow Label').pack(fill=BOTH)
		flow_label_string = StringVar()
		Entry(flow_label, textvariable = flow_label_string, bg = 'white').pack(fill=BOTH)
		flow_label_string.set(header.flow_label)
		flow_label.grid()

		payload_length = Frame(frame, bd = 3, relief = RIDGE)
		payload_length.grid(column = 0, row = 2, columnspan = 5,sticky = (W, E))
		Label(payload_length, text = 'Payload Length').pack(fill=BOTH)
		payload_length_string = StringVar()
		Entry(payload_length, textvariable = payload_length_string, bg = 'white').pack(fill=BOTH)
		payload_length_string.set(header.payload_length)
		payload_length.grid()

		next_header = Frame(frame, bd = 3, relief = RIDGE)
		next_header.grid(column = 5, row = 2, columnspan = 2,sticky = (W, E))
		Label(next_header, text = 'Next Header').pack(fill=BOTH)
		next_header_string = StringVar()
		Entry(next_header, textvariable = next_header_string, bg = 'white').pack(fill=BOTH)
		next_header_string.set(header.next_header)
		next_header.grid()

		hop_limit = Frame(frame, bd = 3, relief = RIDGE)
		hop_limit.grid(column = 7, row = 2, columnspan = 2,sticky = (W, E))
		Label(hop_limit, text = 'Hop Limit').pack(fill=BOTH)
		hop_limit_string = StringVar()
		Entry(hop_limit, textvariable = hop_limit_string, bg = 'white').pack(fill=BOTH)
		hop_limit_string.set(header.hop_limit)
		hop_limit.grid()

		source_address = Frame(frame, bd = 3, relief = RIDGE)
		source_address.grid(column = 0, row = 3, columnspan = 9,sticky = (W, E))
		Label(source_address, text = 'Source Address').pack(fill=BOTH)
		source_address_string = StringVar()
		Entry(source_address, textvariable = source_address_string, bg = 'white').pack(fill=BOTH)
		source_address_string.set(header.source_address)
		source_address.grid()

		destination_address = Frame(frame, bd = 3, relief = RIDGE)
		destination_address.grid(column = 0, row = 4, columnspan = 9,sticky = (W, E))
		Label(destination_address, text = 'Destination Address').pack(fill=BOTH)
		destination_address_string = StringVar()
		Entry(destination_address, textvariable = destination_address_string, bg = 'white').pack(fill=BOTH)
		destination_address_string.set(header.destination_address)
		destination_address.grid()

		hexadecimal_string = Frame(frame, bd = 3, relief = RIDGE)
		hexadecimal_string.grid(column = 0, row = 7, columnspan = 7, sticky = (E,W))
		Label(hexadecimal_string, text = 'Decimal String').pack(fill=BOTH)
		hexadecimal_string_string = StringVar()
		Entry(hexadecimal_string, textvariable = hexadecimal_string_string, bg = 'white').pack(fill=BOTH)
		hexadecimal_string_string.set('')
		hexadecimal_string.grid()

		binary_string = Frame(frame, bd = 3, relief = RIDGE)
		binary_string.grid(column = 0, row = 8, columnspan = 7, sticky = (E,W))
		Label(binary_string, text = 'Binary String').pack(fill=BOTH)
		binary_string_string = StringVar()
		Entry(binary_string, textvariable = binary_string_string, bg = 'white').pack(fill=BOTH)
		binary_string_string.set('')
		binary_string.grid()

		rerun_hexadecimal_string = Frame(frame, bd = 3, relief = RIDGE)
		rerun_hexadecimal_string.grid(column = 0, row = 9, columnspan = 7, sticky = (E,W))
		Label(rerun_hexadecimal_string, text = 'ReRun Decimal String').pack(fill=BOTH)
		rerun_hexadecimal_string_string = StringVar()
		Entry(rerun_hexadecimal_string, textvariable = rerun_hexadecimal_string_string, bg = 'white').pack(fill=BOTH)
		rerun_hexadecimal_string_string.set('')
		rerun_hexadecimal_string.grid()


		button1 = Button(frame, text = "Print", fg = "red",
						 command = lambda: hexadecimal_string_string.set(
								 '-'.join([version_string.get(), traffic_class_string.get(), flow_label_string.get(),
								  payload_length_string.get(), next_header_string.get(), hop_limit_string.get(),
								  source_address_string.get(), destination_address_string.get()])))
		button1.grid(column = 7, row = 7, sticky = (W, E))

		button2 = Button(frame, text = "Convert", fg = "red", command = lambda: binary_string_string.set(analize(hexadecimal_string_string.get())))

		button2.grid(column = 7, row = 8, sticky = (W, E))

		button3 = Button(frame, text = "Convert", fg = "red", command = lambda: rerun_hexadecimal_string_string.set(analize(binary_string_string.get())))

		button3.grid(column = 7, row = 9, sticky = (W, E))

root = Tk()
root.grid_rowconfigure(0, weight = 1)
root.grid_columnconfigure(0, weight = 1)
all = GUI(root)
root.title('IP Header')
root.resizable()
root.mainloop()
