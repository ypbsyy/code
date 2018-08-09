dns_getip is to get your own host ip by capture and analysis the dns response packet   

1.install pcap   
wget http://www.tcpdump.org/release/libpcap-1.4.0.tar.gz   
tar -zxvf libpcap-1.4.0.tar.gz   
cd libpcap-1.4.0   
sudo ./configure   
sudo make   
sudo make install   
    
  
2.compile    
gcc dns_getip.c -lpcap -o dns_getip  
