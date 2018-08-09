dns_getip is to get your own host ip by capture and analysis the dns response packet   

1.install pcap from code   
wget http://www.tcpdump.org/release/libpcap-1.4.0.tar.gz   
tar -zxvf libpcap-1.4.0.tar.gz   
cd libpcap-1.4.0   
sudo ./configure   
sudo make   
sudo make install   

or easy isntall：    
sudo apt-get install libpcap-dev
    
  
2.compile  dns_getip.c  
gcc dns_getip.c -lpcap -o dns_getip  

3.compile test_gethost.c, get host ip by url with calling gethostbyname
gcc -o test_gethost test_gethost.c



