#ifndef MAINWINDOW_H
#define MAINWINDOW_H
#include <pcap.h>
#define HAVE_REMOTE
#include <QMainWindow>
using namespace std;

typedef struct ip_type
{
    u_char byte1;
    u_char byte2;
} ip_type;
//ipv4地址
typedef struct ipv4_address
{
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
} ipv4_address;
//ipv4包头
typedef struct ipv4_header
{
    u_char ver_ihl; // 版本 (4 bits) + 首部长度 (4 bits)
    u_char tos; // 服务类型 (Type of service)
    u_char tlen1; // 总长 (Total length)
    u_char tlen2;
    u_char identification1; // 标识 (Identification)
    u_char identification2;
    u_char flags_fo1; // 标志位 (Flags) (3 bits) + 段偏移量 (Fragment offset) (13 bits)
    u_char flags_fo2;
    u_char ttl; // 存活时间 (Time to live)
    u_char proto; // 协议 (Protocol)
    u_char crc1; // 首部校验和 (Header checksum)
    u_char crc2;
    ipv4_address saddr; // 源地址 (Source address)
    ipv4_address daddr; // 目的地址 (Destination address)
    u_int op_pad; // 选项与填充 (Option + Padding)
} ipv4_header;

//ipv6地址
typedef struct ipv6_address
{
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
    u_char byte5;
    u_char byte6;
    u_char byte7;
    u_char byte8;
    u_char byte9;
    u_char byte10;
    u_char byte11;
    u_char byte12;
    u_char byte13;
    u_char byte14;
    u_char byte15;
    u_char byte16;
} ipv6_address;

//ipv6包头
typedef struct ipv6_header
{
    u_char ver_tc_fl1; // 版本 (4 bits) + 通信质量(Traffic Class)(4 bits) + 流标签(Flow Label)(20 bits)
    u_char ver_tc_fl2;
    u_char ver_tc_fl3;
    u_char ver_tc_fl4;
    u_char pl1; // 有效负荷长度 (Payload Length)(16 bits)
    u_char pl2;
    u_char nh; // 下个报头(Next Header)(8 bits)
    u_char hl; // 跳限制(Hop Limit)(8 bits)
    ipv6_address saddr; // 源IP地址
    ipv6_address daddr; // 目的IP地址
} ipv6_header;

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();

private slots:
    void on_getPacket_clicked();

    void on_split_clicked();

    void on_assemble_clicked();

    void on_TearDrop_clicked();

    void on_DeathOfPing_clicked();

private:
    Ui::MainWindow *ui;
    //界面所需变量
    QString warningInfo;
    QString devInfo;
    QString packetInfo;
    QString analysisInfo;
    QString splitInfo;
    QString assembleInfo;

    //数据报所需变量
    pcap_if_t *alldevs;
    pcap_if_t *d;
    int inum;
    int dev = 0;
    pcap_t *adhandle;
    char errbuf[PCAP_ERRBUF_SIZE];
    ipv4_header* pheader;//ipv4数据
    ipv6_header* pheader1;//ipv6数据
    int packetType;//数据报类型
    int packetLength;//整体长度
    pcap_pkthdr *pkt_header;//头指针
    const u_char *pkt_data;//数据指针
    u_char DF;
    u_char MF;
    struct ipv4_header v4_header[20];
    struct ipv6_header v6_header[20];
    int split_n;
};

#endif // MAINWINDOW_H
