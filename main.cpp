#include <pcap.h>
#include <iostream>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/in.h>

//Функция разложения ethernet-фрейма
u_int16_t ethernet_frame(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
    struct ether_header *eth; //Структура ethernet-заголовка
    eth=(struct ether_header *) packet;//расскладываем наш пакет

    //Далее при выводе использованы специальные функции, позволяющие преобразовать сетевой порядок байт

    printf("Ethernet:\t from: %s", ether_ntoa((struct ether_addr *) &eth->ether_shost));//выводим MAC-адрес отправителя
    printf(" to: %s\n", ether_ntoa((struct ether_addr *) &eth->ether_dhost));//MAC-адрес получателя

    return ntohs(eth->ether_type);//Возвращаем тип пакета, который упакован в наш ethernet-кадр

}

//Описание callback функции
void NewPacket(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char
    *packet)
{

    u_int16_t etype=ethernet_frame(args, pkthdr, packet); //вызываем функцию обрабоки и передаем ей пакет

    //Анализируя возвращаемый тип, выводим информацию о том, что за протокол
    if (etype==ETHERTYPE_IP)
    {printf("(IP)\n"); }

    else if(etype==ETHERTYPE_ARP)
    { printf("(ARP)\n"); }

     else if(etype==ETHERTYPE_REVARP)
    { printf("(RARP)\n"); }

    else if(etype==ETHERTYPE_IPV6)
   { printf("(IP6)\n"); }

    else if(etype==ETHERTYPE_LOOPBACK)
   { printf("(LOOPBACK)\n"); }

    else if(etype==ETHERTYPE_VLAN)
   { printf("(VLAN)\n"); }

    else if(etype==ETHERTYPE_IPX)
   { printf("(IPX)\n"); }

    else { printf("(UNKNOWN)\n"); }
}

int main(int argc, char *argv[])
{
    char *dev = argv[1];
    pcap_t *session;
    char filter[] = "ether multicast";// выражение для фильтра (для примера будем фильтровать multicast пакеты)
    struct bpf_program fp;
    bpf_u_int32 net;
    bpf_u_int32 mask;
    char errbuf[PCAP_ERRBUF_SIZE];
       // dev = pcap_lookupdev(errbuf);//Определяем устройство (берем первое подходящее)
        if (dev == NULL)
        {
            fprintf(stderr, "Couldn't find device: %s\n", errbuf);
            return(2);
        }
    pcap_lookupnet(dev, &net, &mask, errbuf); //определяем маску и сетевой адрес устройства

    session = pcap_open_live(dev, BUFSIZ, 1, -1, errbuf); //открываем сессию

    pcap_compile(session, &fp,filter, 0, net); //Компиляция фильтра
    pcap_setfilter(session, &fp);// Запуск фильтра

    pcap_loop(session, -1, NewPacket, NULL); //в лупе вызываем callback функцию



    pcap_close(session);
    return(0);
}

