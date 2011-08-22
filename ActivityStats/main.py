from ActivityStats import ActivityStats

#file_str = raw_input("Enter a file time to process: ")
file_str = '20101128000001'

AS = ActivityStats()
flows, iplist = AS.hwdb_extract(file_str, 1, 1440, 3660)
print(len(flows),"hours extracted")
