# ababuselist
AB Data AbuseIPDB list sanitizer

This utility massages a AbuseIPDB CSV file to remove any duplicates before submission. My public machines are well within the normal submission limitations if no duplicates are sent. Because there is no easy way to uniq just on the IP address field in the CSV, I decided to load the addresses into a sorted list. I don't try to be effecient with inserts. I just scan from the first address until I find the place to insert or that the current address is a duplicate for discard.

This utility is the final step after grepping the desired log entries that pass through an awk script to transform a syslog entry into the format of the AbuseIPDB CSV file: IP, Categories, Report Date and Comment. The utility reads stdin for this data, parses the fields, determines if this is a new address or duplicate. New addresses are inserted into the sorted doubly-linked list with all the fields stored. If the address is a duplicate, the current line is discarded. When input is complete, the progam runs through the list outputting the fields to stdout.

There's a kludge on line 538 because I somehow would end up with an address that occurred somewhere within the list to be duplicated as the last entry in the linked list. I could never see this happen while stepping through in the debugger, so I added the kludge to make sure that the next IPv4 address is greater than the last one we output.
