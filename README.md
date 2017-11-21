# netdump
Simple tcpdump analog with build-in cron function.

Why to create: tcpdump has option -G to ratate file every N seconds. But I need file save for example exectly every 15 minutes, that is 00:15:00, 00:30:00, 00:45:00, 01:00:00.

Required params:
- -i - name of interface. Can use to -D option to list available interfaces
 - --cron - specify interval in cron format. 
 For example: every hour "0 0 */1 * * *"
 - -w - file name. Name must include field from in strftime format http://strftime.org/.
 For example: For example: %Y%m%d_%H%M%S.pcap will produce 20171121_220010.pcap (2017 November 21 22:00:10)

Optional params:
- -z - specify coomand invoked after file will be closed. for example zip `-z "gzip -9"`
- -s,--snapshot-length - length of packet to save

And like in tcpdump can specify BPF expression
