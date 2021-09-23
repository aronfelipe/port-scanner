import nmap
nmScan = nmap.PortScanner()
host_input = input("Digite o host que deseja fazer o port scan: ")
range_input = input("Digite um range de portas, exemplo (22-8180): ")
print(nmScan.scan(host_input, range_input))

for host in nmScan.all_hosts():
    print('Host : %s (%s)' % (host, nmScan[host].hostname()))
    print('State : %s' % nmScan[host].state())
    for proto in nmScan[host].all_protocols():
        print('----------')
        print('Protocol : %s' % proto)

        lport = nmScan[host][proto].keys()
        for port in lport:
            print ('port : %s\tstate : %s' % (port, nmScan[host][proto][port]['state']))