#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <pcap.h>
#include <remote-ext.h>
#define HAVE_REMOTE
using namespace std;

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    packetType = -1;
    packetLength = 0;
//文本框设置为只读
   ui->devInfo->setReadOnly(true);
   ui->packetInfo->setReadOnly(true);
   ui->analysisInfo->setReadOnly(true);
   ui->splitInfo->setReadOnly(true);
   ui->assembleInfo->setReadOnly(true);
//按钮禁用
   ui->split->setEnabled(false);
   ui->assemble->setEnabled(false);
   ui->TearDrop->setEnabled(false);
   ui->DeathOfPing->setEnabled(false);
//获取本机设备列表
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
    {
        QString st = errbuf;
        warningInfo = "Error in pcap_findalldevs: " + st;
        ui->warningText->setText(warningInfo);
        exit(1);
    }

//打印列表
    QString fgx = "-------------------------------------------------------------------------\n";
    devInfo = "网卡序号\t\t\t\t名称及描述\n";
    devInfo = devInfo + fgx;
    for (d = alldevs; d; d = d->next)
    {
        dev++;
        //网卡的序号和名称
        devInfo = devInfo + "网卡" + QString::number(dev,10) + "\t" + d->name + "\n" ;
        //网卡的描述
        devInfo = devInfo + "\t";
        if (d->description)
            devInfo = devInfo + d->description + "\n";
        else
            devInfo = devInfo + "No description available\n";
        devInfo = devInfo + fgx;
        //在ChomoBox中添加
        QString st = "网卡" + QString::number(dev,10);
        ui->comboBox->addItem(st);
    }
    //没有设备
    if (dev == 0)
    {
        ui->warningText->setText("\nNo interfaces found! Make sure WinPcap is installed.\n");
    }
    //显示网卡所有信息
    ui->devInfo->setText(devInfo);
}

MainWindow::~MainWindow()
{
    delete ui;
}
u_short char2short(u_char c1, u_char c2)
{
    u_short t,t1,t2;//t1为前8位，t2为后8位
    t1 = c1 & 0x00ff;
    t1 = (t1 << 8) & 0xff00;
    t2 = c2 & 0x00ff;
    t = t1 | t2;
    return t;
}
//crc计算
u_short crc_cal(ipv4_header v4)
{
    u_short crc = 0x0000;
    u_short t;
    //拼接版本、首部长度、服务类型
    t = char2short(v4.ver_ihl, v4.tos);
    crc = crc + t ^ 0xffff;//取反码求和
    //数据包长度
    t = char2short(v4.tlen1, v4.tlen2);
    crc = crc + t ^ 0xffff;//取反码求和
    //标识
    t = char2short(v4.identification1, v4.identification2);
    crc = crc + t ^ 0xffff;//取反码求和
    //标志位+偏移量
    t = char2short(v4.flags_fo1, v4.flags_fo2);
    crc = crc + t ^ 0xffff;//取反码求和
    //存活时间、协议
    t = char2short(v4.ttl, v4.proto);
    crc = crc + t ^ 0xffff;//取反码求和
    //首部校验和
    t = 0x0000;
    crc = crc + t ^ 0xffff;//取反码求和
    //源IP地址
    t = char2short(v4.saddr.byte1, v4.saddr.byte2);
    crc = crc + t ^ 0xffff;//取反码求和
    t = char2short(v4.saddr.byte3, v4.saddr.byte4);
    crc = crc + t ^ 0xffff;//取反码求和
    //目的IP地址
    t = char2short(v4.daddr.byte1, v4.daddr.byte2);
    crc = crc + t ^ 0xffff;//取反码求和
    t = char2short(v4.daddr.byte3, v4.daddr.byte4);
    crc = crc + t ^ 0xffff;//取反码求和

    return crc;
}
void MainWindow::on_getPacket_clicked()
{
    ui->splitInfo->clear();
    ui->assembleInfo->clear();
    //获取指定网卡序号
    int inum = ui->comboBox->currentIndex() + 1;
    warningInfo = "从网卡" + QString::number(inum,10) + "中...";
    ui->warningText->setText(warningInfo);

    //抓包
    /* 跳转到选中的适配器 */
    for (d = alldevs, dev = 0; dev< inum - 1; d = d->next, dev++);

    /* 打开设备 */
    if ((adhandle = pcap_open(d->name,          // 设备名
        65535,            // 65535保证能捕获到不同数据链路层上的每个数据包的全部内容
        PCAP_OPENFLAG_PROMISCUOUS,    // 混杂模式
        1000,             // 读取超时时间
        NULL,             // 远程机器验证
        errbuf            // 错误缓冲池
    )) == NULL)
    {
        warningInfo = "Unable to open the adapter. 网卡" + QString::number(inum,10) + " is not supported by WinPcap";
        ui->warningText->setText(warningInfo);

        /* 释放设备列表 */
        pcap_freealldevs(alldevs);
    }

    warningInfo = "listening on 网卡" + QString::number(inum,10) + "...";
    ui->warningText->setText(warningInfo);

    pcap_t * handler;
    if (NULL == (handler = pcap_open(d->name, 65535, PCAP_OPENFLAG_PROMISCUOUS, 3000, NULL, errbuf))) {
        //设置接受的包大小为65535，即可以接受所有大小的包
        QString stt = errbuf;
        warningInfo = "err in pcap_open :" + stt;
        ui->warningText->setText(warningInfo);
    }

    packetInfo = "";
    if (1 == pcap_next_ex(handler, &pkt_header, &pkt_data)) {
        packetLength = pkt_header->len;
        for (int k = 0; k < packetLength; k++) {//输出所有数据
            if (k % 16 == 0 && k != 0)//一排十六个
                packetInfo = packetInfo + "\n";
            int t = *(pkt_data + k);
            QString st =  QString("%1").arg(t,2,16,QLatin1Char('0'));
            packetInfo = packetInfo + st + " ";
        }
        warningInfo = "抓包成功";
        ui->warningText->setText(warningInfo);
    }
    else{
        warningInfo = "抓包失败，请重新抓取";
        ui->warningText->setText(warningInfo);
        return;
    }
    ui->packetInfo->setText(packetInfo);

//解析数据包
    ip_type* type = (ip_type *)(pkt_data + 12);
    //判断
    if(type->byte1-0 == 0x08 && type->byte2-0 == 0x00)//ipv4
    {
        analysisInfo = "";
        packetType = 4;
        pheader = (ipv4_header *)(pkt_data + 14);
        //版本
        char ver_ihl = pheader->ver_ihl;
        char ver = ver_ihl >> 4;
        analysisInfo = analysisInfo + "版本号：\t\t" + QString::number(ver-0,16) + "\n";
        //首部长度
        u_char ihl = ver_ihl & 0x0f;
        analysisInfo = analysisInfo + "首部长度(10)：\t" + QString::number(ihl-0,10) + "\n";
        //服务类型
        analysisInfo = analysisInfo + "服务类型：\t\t" + QString("%1").arg(pheader->tos-0,2,16,QLatin1Char('0')) + "\n";
        //数据包长度
        u_short lt = char2short(pheader->tlen1,pheader->tlen2);
        analysisInfo = analysisInfo + "数据包长度(10)：\t" + QString::number(lt,10) + "\n";
        //标识
        analysisInfo = analysisInfo + "标识：\t\t" + QString("%1").arg(pheader->identification1,2,16,QLatin1Char('0')) + QString("%1").arg(pheader->identification2,2,16,QLatin1Char('0')) + "\n";
        //标志位
        u_char flags_fo1 = pheader->flags_fo1;
        u_char flags = (flags_fo1 >> 5) & 0x07;
        DF = (flags >> 1) & 0x01;
        MF = flags & 0x01;
        analysisInfo = analysisInfo + "DF：\t\t" + QString::number(DF-0,2) + "\n";
        analysisInfo = analysisInfo + "MF：\t\t" + QString::number(MF-0,2) + "\n";
        //片偏移
        u_short flags_fo2 = pheader->flags_fo2;
        u_short fo = ((flags_fo1 & 0x1f) << 8) | (flags_fo2 & 0x00ff);
        analysisInfo = analysisInfo + "片偏移量(10)：\t" + QString::number(fo,10) + "\n";
        //TTL
        analysisInfo = analysisInfo + "存活时间(10)：\t" + QString::number(pheader->ttl,10) + "\n";
        //上层协议
        analysisInfo = analysisInfo + "上层协议：\t\t" + QString("%1").arg(pheader->proto,2,16,QLatin1Char('0')) + "\n";
        //首部校验和
        analysisInfo = analysisInfo + "首部校验和：\t" + QString("%1").arg(pheader->crc1,2,16,QLatin1Char('0')) + QString("%1").arg(pheader->crc2,2,16,QLatin1Char('0')) + "\n";
        //源IP地址
        QString sip = QString::number(pheader->saddr.byte1,10) + ".";
        sip = sip + QString::number(pheader->saddr.byte2,10) + ".";
        sip = sip + QString::number(pheader->saddr.byte3,10) + ".";
        sip = sip + QString::number(pheader->saddr.byte4,10);
        analysisInfo = analysisInfo + "源IP地址：\t\t" + sip + "\n";
        //目的IP地址
        QString dip = QString::number(pheader->daddr.byte1,10) + ".";
        dip = dip + QString::number(pheader->daddr.byte2,10) + ".";
        dip = dip + QString::number(pheader->daddr.byte3,10) + ".";
        dip = dip + QString::number(pheader->daddr.byte4,10);
        analysisInfo = analysisInfo + "目的IP地址：\t" + dip + "\n";
        //输出
        ui->analysisInfo->setText(analysisInfo);
        warningInfo = "ipv4数据包 解析成功";
        ui->warningText->setText(warningInfo);
    }
    else if(type->byte1-0 == 0x86 && type->byte2-0 == 0xdd){//ipv6
        pheader1 = (ipv6_header *)(pkt_data + 14);
        analysisInfo = "";
        packetType = 6;
        //版本
        u_char ver_tc_fl1 = pheader1->ver_tc_fl1;
        u_char ver = (ver_tc_fl1 >> 4) & 0x0f;
        analysisInfo = analysisInfo + "版本号：\t\t" + QString::number(ver-0,16) + "\n";
        //通信质量
        u_short ver_tc_fl2 = pheader1->ver_tc_fl2;
        u_short tc = ((ver_tc_fl1 & 0x000f) << 4) | ((ver_tc_fl2 & 0x00f0) >> 4);
        analysisInfo = analysisInfo + "通信质量：\t\t" + QString("%1").arg(tc-0,2,16,QLatin1Char('0')) + "\n";
        //流标签
        u_short ver_tc_fl3 = pheader1->ver_tc_fl3;
        u_int ver_tc_fl4 = pheader1->ver_tc_fl4;
        u_int fl = ((ver_tc_fl2 & 0x0000000f) << 16) | ((ver_tc_fl3 & 0x0000ffff) << 8) | ver_tc_fl4 & 0x0000ffff;
        analysisInfo = analysisInfo + "流标签：\t\t" + QString::number(fl-0,16) + "\n";
        //有效负荷长度
        u_short ltt = char2short(pheader1->pl1, pheader1->pl2);
        analysisInfo = analysisInfo + "有效负荷长度(10)：\t" + QString::number(ltt,10) + "\n";
        //下一报头
        analysisInfo = analysisInfo + "下一报头：\t\t" + QString("%1").arg(pheader1->nh,2,16,QLatin1Char('0')) + "\n";
        //跳限制
        analysisInfo = analysisInfo + "跳限制(10)：\t" + QString::number(pheader1->hl,10) + "\n";
        //源IP地址
        QString sip = QString("%1").arg(pheader1->saddr.byte1,2,16,QLatin1Char('0')) + QString("%1").arg(pheader1->saddr.byte2,2,16,QLatin1Char('0')) + ":";
        sip = sip + QString("%1").arg(pheader1->saddr.byte3,2,16,QLatin1Char('0')) + QString("%1").arg(pheader1->saddr.byte4,2,16,QLatin1Char('0')) + ":";
        sip = sip + QString("%1").arg(pheader1->saddr.byte5,2,16,QLatin1Char('0')) + QString("%1").arg(pheader1->saddr.byte6,2,16,QLatin1Char('0')) + ":";
        sip = sip + QString("%1").arg(pheader1->saddr.byte7,2,16,QLatin1Char('0')) + QString("%1").arg(pheader1->saddr.byte8,2,16,QLatin1Char('0')) + ":";
        sip = sip + QString("%1").arg(pheader1->saddr.byte9,2,16,QLatin1Char('0')) + QString("%1").arg(pheader1->saddr.byte10,2,16,QLatin1Char('0')) + ":";
        sip = sip + QString("%1").arg(pheader1->saddr.byte11,2,16,QLatin1Char('0')) + QString("%1").arg(pheader1->saddr.byte12,2,16,QLatin1Char('0')) + ":";
        sip = sip + QString("%1").arg(pheader1->saddr.byte13,2,16,QLatin1Char('0')) + QString("%1").arg(pheader1->saddr.byte14,2,16,QLatin1Char('0')) + ":";
        sip = sip + QString("%1").arg(pheader1->saddr.byte15,2,16,QLatin1Char('0')) + QString("%1").arg(pheader1->saddr.byte16,2,16,QLatin1Char('0'));
        analysisInfo = analysisInfo + "源IP地址：\n\t" + sip + "\n";
        //目的IP地址
        QString dip = QString("%1").arg(pheader1->daddr.byte1,2,16,QLatin1Char('0')) + QString("%1").arg(pheader1->daddr.byte2,2,16,QLatin1Char('0')) + ":";
        dip = dip + QString("%1").arg(pheader1->daddr.byte3,2,16,QLatin1Char('0')) + QString("%1").arg(pheader1->daddr.byte4,2,16,QLatin1Char('0')) + ":";
        dip = dip + QString("%1").arg(pheader1->daddr.byte5,2,16,QLatin1Char('0')) + QString("%1").arg(pheader1->daddr.byte6,2,16,QLatin1Char('0')) + ":";
        dip = dip + QString("%1").arg(pheader1->daddr.byte7,2,16,QLatin1Char('0')) + QString("%1").arg(pheader1->daddr.byte8,2,16,QLatin1Char('0')) + ":";
        dip = dip + QString("%1").arg(pheader1->daddr.byte9,2,16,QLatin1Char('0')) + QString("%1").arg(pheader1->daddr.byte10,2,16,QLatin1Char('0')) + ":";
        dip = dip + QString("%1").arg(pheader1->daddr.byte11,2,16,QLatin1Char('0')) + QString("%1").arg(pheader1->daddr.byte12,2,16,QLatin1Char('0')) + ":";
        dip = dip + QString("%1").arg(pheader1->daddr.byte13,2,16,QLatin1Char('0')) + QString("%1").arg(pheader1->daddr.byte14,2,16,QLatin1Char('0')) + ":";
        dip = dip + QString("%1").arg(pheader1->daddr.byte15,2,16,QLatin1Char('0')) + QString("%1").arg(pheader1->daddr.byte16,2,16,QLatin1Char('0'));
        analysisInfo = analysisInfo + "目的IP地址：\n\t" + dip + "\n";
        //输出
        ui->analysisInfo->setText(analysisInfo);
        warningInfo = "ipv6数据包 解析成功";
        ui->warningText->setText(warningInfo);
    }
    ui->split->setEnabled(true);
    ui->assemble->setEnabled(false);
    ui->TearDrop->setEnabled(false);
    ui->DeathOfPing->setEnabled(false);
}
//输出数据包内容
QString packet_ipv4_dis(ipv4_header p, int type = 0){
    QString dis = "";
    if(type == 0)
        dis = dis + QString("%1").arg(p.ver_ihl,2,16,QLatin1Char('0')) + " " + QString("%1").arg(p.tos,2,16,QLatin1Char('0')) + "\n";
    else
        dis = dis + QString("%1").arg(p.ver_ihl,2,16,QLatin1Char('0')) + " " + QString("%1").arg(p.tos,2,16,QLatin1Char('0')) + " ";
    dis = dis + QString("%1").arg(p.tlen1,2,16,QLatin1Char('0')) + " " + QString("%1").arg(p.tlen2,2,16,QLatin1Char('0')) + " ";
    dis = dis + QString("%1").arg(p.identification1,2,16,QLatin1Char('0')) + " " + QString("%1").arg(p.identification2,2,16,QLatin1Char('0')) + " ";
    dis = dis + QString("%1").arg(p.flags_fo1,2,16,QLatin1Char('0')) + " " + QString("%1").arg(p.flags_fo2,2,16,QLatin1Char('0')) + " ";
    dis = dis + QString("%1").arg(p.ttl,2,16,QLatin1Char('0')) + " " + QString("%1").arg(p.proto,2,16,QLatin1Char('0')) + " ";
    dis = dis + QString("%1").arg(p.crc1,2,16,QLatin1Char('0')) + " " + QString("%1").arg(p.crc2,2,16,QLatin1Char('0')) + " ";
    dis = dis + QString("%1").arg(p.saddr.byte1,2,16,QLatin1Char('0')) + " " + QString("%1").arg(p.saddr.byte2,2,16,QLatin1Char('0')) + " ";
    dis = dis + QString("%1").arg(p.saddr.byte3,2,16,QLatin1Char('0')) + " " + QString("%1").arg(p.saddr.byte4,2,16,QLatin1Char('0')) + " ";
    if(type == 0)
        dis = dis + QString("%1").arg(p.daddr.byte1,2,16,QLatin1Char('0')) + " " + QString("%1").arg(p.daddr.byte2,2,16,QLatin1Char('0')) + "\n";
    else
        dis = dis + QString("%1").arg(p.daddr.byte1,2,16,QLatin1Char('0')) + " " + QString("%1").arg(p.daddr.byte2,2,16,QLatin1Char('0')) + " ";
    dis = dis + QString("%1").arg(p.daddr.byte3,2,16,QLatin1Char('0')) + " " + QString("%1").arg(p.daddr.byte4,2,16,QLatin1Char('0')) + " ";
    return dis;
}
QString packet_ipv6_dis(ipv6_header p, int type = 0){
    QString dis = "";
    if(type == 0)
        dis = dis + QString("%1").arg(p.ver_tc_fl1,2,16,QLatin1Char('0')) + " " + QString("%1").arg(p.ver_tc_fl2,2,16,QLatin1Char('0')) + "\n";
    else
        dis = dis + QString("%1").arg(p.ver_tc_fl1,2,16,QLatin1Char('0')) + " " + QString("%1").arg(p.ver_tc_fl2,2,16,QLatin1Char('0')) + " ";
    dis = dis + QString("%1").arg(p.ver_tc_fl3,2,16,QLatin1Char('0')) + " " + QString("%1").arg(p.ver_tc_fl4,2,16,QLatin1Char('0')) + " ";
    dis = dis + QString("%1").arg(p.pl1,2,16,QLatin1Char('0')) + " " + QString("%1").arg(p.pl2,2,16,QLatin1Char('0')) + " ";
    dis = dis + QString("%1").arg(p.nh,2,16,QLatin1Char('0')) + " " + QString("%1").arg(p.hl,2,16,QLatin1Char('0')) + " ";
    dis = dis + QString("%1").arg(p.saddr.byte1,2,16,QLatin1Char('0')) + " " + QString("%1").arg(p.saddr.byte2,2,16,QLatin1Char('0')) + " ";
    dis = dis + QString("%1").arg(p.saddr.byte3,2,16,QLatin1Char('0')) + " " + QString("%1").arg(p.saddr.byte4,2,16,QLatin1Char('0')) + " ";
    dis = dis + QString("%1").arg(p.saddr.byte5,2,16,QLatin1Char('0')) + " " + QString("%1").arg(p.saddr.byte6,2,16,QLatin1Char('0')) + " ";
    dis = dis + QString("%1").arg(p.saddr.byte7,2,16,QLatin1Char('0')) + " " + QString("%1").arg(p.saddr.byte8,2,16,QLatin1Char('0')) + " ";
    if(type == 0)
        dis = dis + QString("%1").arg(p.saddr.byte9,2,16,QLatin1Char('0')) + " " + QString("%1").arg(p.saddr.byte10,2,16,QLatin1Char('0')) + "\n";
    else
        dis = dis + QString("%1").arg(p.saddr.byte9,2,16,QLatin1Char('0')) + " " + QString("%1").arg(p.saddr.byte10,2,16,QLatin1Char('0')) + " ";
    dis = dis + QString("%1").arg(p.saddr.byte11,2,16,QLatin1Char('0')) + " " + QString("%1").arg(p.saddr.byte12,2,16,QLatin1Char('0')) + " ";
    dis = dis + QString("%1").arg(p.saddr.byte13,2,16,QLatin1Char('0')) + " " + QString("%1").arg(p.saddr.byte14,2,16,QLatin1Char('0')) + " ";
    dis = dis + QString("%1").arg(p.saddr.byte15,2,16,QLatin1Char('0')) + " " + QString("%1").arg(p.saddr.byte16,2,16,QLatin1Char('0')) + " ";
    dis = dis + QString("%1").arg(p.daddr.byte1,2,16,QLatin1Char('0')) + " " + QString("%1").arg(p.daddr.byte2,2,16,QLatin1Char('0')) + " ";
    dis = dis + QString("%1").arg(p.daddr.byte3,2,16,QLatin1Char('0')) + " " + QString("%1").arg(p.daddr.byte4,2,16,QLatin1Char('0')) + " ";
    dis = dis + QString("%1").arg(p.daddr.byte5,2,16,QLatin1Char('0')) + " " + QString("%1").arg(p.daddr.byte6,2,16,QLatin1Char('0')) + " ";
    dis = dis + QString("%1").arg(p.daddr.byte7,2,16,QLatin1Char('0')) + " " + QString("%1").arg(p.daddr.byte8,2,16,QLatin1Char('0')) + " ";
    if(type == 0)
        dis = dis + QString("%1").arg(p.daddr.byte9,2,16,QLatin1Char('0')) + " " + QString("%1").arg(p.daddr.byte10,2,16,QLatin1Char('0')) + "\n";
    else
        dis = dis + QString("%1").arg(p.daddr.byte9,2,16,QLatin1Char('0')) + " " + QString("%1").arg(p.daddr.byte10,2,16,QLatin1Char('0')) + " ";
    dis = dis + QString("%1").arg(p.daddr.byte11,2,16,QLatin1Char('0')) + " " + QString("%1").arg(p.daddr.byte12,2,16,QLatin1Char('0')) + " ";
    dis = dis + QString("%1").arg(p.daddr.byte13,2,16,QLatin1Char('0')) + " " + QString("%1").arg(p.daddr.byte14,2,16,QLatin1Char('0')) + " ";
    dis = dis + QString("%1").arg(p.daddr.byte15,2,16,QLatin1Char('0')) + " " + QString("%1").arg(p.daddr.byte16,2,16,QLatin1Char('0')) + " ";
    return dis;
}
void MainWindow::on_split_clicked()
{
    splitInfo = "";
    if(packetType == 4){
        //检测是否可分,DF=1不可分
//        u_char df = (pheader->flags_fo1 >> 6) & 0x0001;
//        if(df-0 == 1)
//        {
//            warningInfo = "DF=1，不可分";
//            ui->splitInfo->setText(warningInfo);
//            return;
//        }
        //MTU
        QString MTU = ui->mtu->text();
        double mtu = MTU.toDouble();
        //IP分组总数据长度
        double ip_data_length = packetLength - 14 - 20;
        if(ip_data_length + 20 <= mtu || mtu <= 20)
        {
            warningInfo = "不可再分，请调整MTU数值";
            ui->warningText->setText(warningInfo);
            return;
        }
        //每帧可承载数据
        double max_data = floor((mtu-20)/8)*8;
        //分片数
        split_n = ceil(ip_data_length/max_data);
        //每片偏移量
        int ip_fo = max_data / 8;
        //开始分片
        for(int i = 0; i < split_n; i++)
        {
            //直接复制的数据
            v4_header[i].ver_ihl = pheader->ver_ihl;//版本号+首部长度
            v4_header[i].tos = pheader->tos;//服务类型
            v4_header[i].identification1 = pheader->identification1;//标识
            v4_header[i].identification2 = pheader->identification2;
            v4_header[i].proto = pheader->proto;//上层协议
            v4_header[i].saddr = pheader->saddr;//源IP地址
            v4_header[i].daddr = pheader->daddr;//目的IP地址
            //待处理的数据
            //标志位+片偏移
            u_char flags_fo1t,flags_fo2t;
            u_char flags;
            if(i != split_n - 1){//不是最后一片
                //DF=0,MF=1
                flags = 0x00 | 0x01;
            }
            else{//最后一片
                //DF=0,MF=0
                flags = 0x00 | 0x00;
            }
            //拼接flags_fo1t
            flags_fo1t = flags << 5;//标志位左移5位，到最终位置
            u_short fot = i * ip_fo;//偏移量
            fot = fot & 0x1fff;//除低13位外清零
            fot = (fot >> 8) & 0x001f;//保留13位中的高5位
            flags_fo1t = flags_fo1t | (u_char)fot;//将这5位保存
            //拼接flags_fo2t
            fot = i * ip_fo;
            fot = fot & 0x00ff;//除低8位外清零
            flags_fo2t = (u_char)fot;//保存这8位
            //保存
            v4_header[i].flags_fo1 = flags_fo1t;
            v4_header[i].flags_fo2 = flags_fo2t;

            //ttl
            v4_header[i].ttl = pheader->ttl - 1;

            //总长
            u_short tlent;
            if(i != split_n - 1){//不是最后一片
                tlent = 20 + ip_fo * 8;//总长度
            }
            else{
                tlent = 20 + ip_data_length - ip_fo * 8 * (split_n - 1);
            }
            v4_header[i].tlen1 = (u_char)((tlent >> 8) & 0x00ff);//保存高8位
            v4_header[i].tlen2 = (u_char)(tlent & 0x00ff);//保存低8位
            //首部校验和
            u_short crct = crc_cal(v4_header[i]);
            u_short crcth = (crct >> 8) & 0x00ff;//高8位
            u_short crctl = crct * 0x00ff;
            v4_header[i].crc1 = (u_char)crcth;
            v4_header[i].crc2 = (u_char)crctl;
            //输出
            splitInfo = splitInfo + "-----------------第" + QString::number(i+1,10) + "片-----------------\n";

            //帧头
            splitInfo = splitInfo + "帧头：\n";
            for (int k = 0; k < 14; k++) {
                int t = *(pkt_data + k);
                QString st =  QString("%1").arg(t,2,16,QLatin1Char('0'));
                splitInfo = splitInfo + st + " ";
            }
            splitInfo = splitInfo + "\n";
            //ip头
            splitInfo = splitInfo + "IP头：\n";
            splitInfo = splitInfo + packet_ipv4_dis(v4_header[i], 1) + "\n";
            //IP报数据
            splitInfo = splitInfo + "数据：\n";
            int start = 34 + i*ip_fo*8;
            for (int k = start; k < start+tlent-20; k++) {
                int t = *(pkt_data + k);
                QString st =  QString("%1").arg(t,2,16,QLatin1Char('0'));
                splitInfo = splitInfo + st + " ";
            }
            splitInfo = splitInfo + "\n";

            //解析
            splitInfo = splitInfo + "数据包长度：\t" + QString::number(tlent,10) + "\n";
            splitInfo = splitInfo + "标识：\t\t" + QString("%1").arg(v4_header[i].identification1,2,16,QLatin1Char('0')) + QString("%1").arg(v4_header[i].identification2,2,16,QLatin1Char('0')) + "\n";
            splitInfo = splitInfo + "DF、MF：\t\t" + QString("%1").arg(flags,2,2,QLatin1Char('0')) + "\n";
            splitInfo = splitInfo + "偏移量：\t\t" + QString::number(i * ip_fo,10) + "\n";
            ui->splitInfo->setText(splitInfo);
            warningInfo = "ipv4数据包 分片成功";
            ui->warningText->setText(warningInfo);
        }
    }
    else{//ipv6数据包
        //MTU
        QString MTU = ui->mtu->text();
        double mtu = MTU.toDouble();
        //IP分组数据长度
        double ip_data_length = packetLength - 14 - 40;
        if(ip_data_length + 40 <= mtu || mtu <= 40)
        {
            warningInfo = "不可再分，请调整MTU数值";
            ui->warningText->setText(warningInfo);
            return;
        }
        //每帧可承载数据
        double max_data = mtu - 40;
        //分片数
        split_n = ceil(ip_data_length/max_data);
        for(int i = 0; i < split_n; i++)
        {
            //直接复制的数据
            v6_header[i].ver_tc_fl1 = pheader1->ver_tc_fl1;//版本、通信质量、流标签
            v6_header[i].ver_tc_fl2 = pheader1->ver_tc_fl2;
            v6_header[i].ver_tc_fl3 = pheader1->ver_tc_fl3;
            v6_header[i].ver_tc_fl4 = pheader1->ver_tc_fl4;
            v6_header[i].nh = pheader1->nh;//下个报头
            v6_header[i].saddr = pheader1->saddr;//源IP地址
            v6_header[i].daddr = pheader1->daddr;//目的IP地址
            //有效负荷长度
            u_short tlent;
            if(i != split_n - 1){//不是最后一片
                tlent = max_data;
            }
            else{
                tlent = ip_data_length - max_data * (split_n - 1);
            }
            v6_header[i].pl1 = (u_char)((tlent >> 8) & 0x00ff);//保存高8位
            v6_header[i].pl2 = (u_char)(tlent & 0x00ff);//保存低8位
            //跳限制
            v6_header[i].hl = pheader1->hl;
            //输出
            splitInfo = splitInfo + "-----------------第" + QString::number(i+1,10) + "片-----------------\n";
            //帧头
            splitInfo = splitInfo + "帧头：\n";
            for (int k = 0; k < 14; k++) {
                int t = *(pkt_data + k);
                QString st =  QString("%1").arg(t,2,16,QLatin1Char('0'));
                splitInfo = splitInfo + st + " ";
            }
            splitInfo = splitInfo + "\n";
            //ip头
            splitInfo = splitInfo + "IP头：\n";
            splitInfo = splitInfo + packet_ipv6_dis(v6_header[i],1) + "\n";
            //IP报数据
            splitInfo = splitInfo + "数据：\n";
            int start = 14 + 40 + i * max_data;
            for (int k = start; k < start + tlent; k++) {
                int t = *(pkt_data + k);
                QString st =  QString("%1").arg(t,2,16,QLatin1Char('0'));
                splitInfo = splitInfo + st + " ";
            }
            splitInfo = splitInfo + "\n";

            //解析
            splitInfo = splitInfo + "有效载荷(10)：\t" + QString::number(tlent,10) + "\n";
            ui->splitInfo->setText(splitInfo);
            warningInfo = "ipv6数据包 分片成功";
            ui->warningText->setText(warningInfo);
        }
    }
    ui->assemble->setEnabled(true);
    ui->TearDrop->setEnabled(true);
    ui->DeathOfPing->setEnabled(true);
}

void MainWindow::on_assemble_clicked()
{
    assembleInfo = "";
    if(packetType == 4){
        long long sum = 0;
        int mf[split_n];//MF值
        int fo[split_n];//片偏移量
        u_short length[split_n];//每个数据包数据长度
        //处理每个数据包
        for(int i = 0; i < split_n; i++)
        {
            //获取MF
            u_char mft = (v4_header[i].flags_fo1 >> 5) & 0x01;
            mf[i] = mft - 0;
            //获取偏移量
            u_short fot = char2short(v4_header[i].flags_fo1, v4_header[i].flags_fo2);
            fot = fot & 0x1fff;
            fo[i] = fot;
            //获取数据长度
            u_short lt = char2short(v4_header[i].tlen1,v4_header[i].tlen2) - 20;
            length[i] = lt;
        }
        //death of ping
        for(int i = 0; i < split_n; i++)
        {
            sum += length[i];
        }
        if(sum > 65535)
        {
            warningInfo = "Death of Ping";
            ui->assembleInfo->setText(warningInfo);
            return;
        }

        //检测TearDrop
        /*
         * 思路：所有分片可以分为若干个等长片或带一个不能长片，计算其中一个等长片的长度，得到每片之间的偏移量的差。
         *      遍历每个分片，如果某片的偏移量不能整除偏移量的差，则说明重叠。
         */
        //计算偏移量的差值
        int n_of_piece;
        for(int i = 0; i < split_n; i++)
        {
            if(mf[i] != 0)
            {
                n_of_piece = length[i];
                break;
            }
        }
        n_of_piece /= 8;
        //遍历
        bool td[split_n];
        for(int i = 0; i < split_n; i++)
            td[i] = false;
        for(int i = 0; i < split_n; i++)
        {
            double t1;
            int t2;
            t1 = (double)fo[i]/(double)n_of_piece;
            t2 = fo[i]/n_of_piece;
            if(t1 - t2 != 0)//不为整数，重叠
            {
                warningInfo = "TearDrop，偏移量错位";
                ui->assembleInfo->setText(warningInfo);
                return;
            }
            else{
                td[t2] = true;
            }
        }
        for(int i = 0; i < split_n; i++)
        {
            if(td[i] != true)
            {
                warningInfo = "TearDrop，数据包缺失";
                ui->assembleInfo->setText(warningInfo);
                return;
            }
        }
        //输出
        assembleInfo = "ipv4数据包数据流：\n";
        //帧头
        for (int k = 0; k < 14; k++) {
            int t = *(pkt_data + k);
            QString st =  QString("%1").arg(t,2,16,QLatin1Char('0'));
            assembleInfo = assembleInfo + st + " ";
        }
        //ip数据包头
        //长度
        int ltt = sum + 20;
        u_char th,tl;
        th = (u_char)((ltt >> 8) & 0x00ff);//保存高8位
        tl = (u_char)(ltt & 0x00ff);//保存低8位
        v4_header[0].tlen1 = th;
        v4_header[0].tlen2 = tl;
        //标志位、片偏移
        u_short ft = 0x0000;
        th = (u_char)((ft >> 8) & 0x00ff);//保存高8位
        tl = (u_char)(ft & 0x00ff);//保存低8位
        v4_header[0].flags_fo1 = th;
        v4_header[0].flags_fo2 = tl;
        //校验和
        u_char crc0 = 0x00;
        v4_header[0].crc1 = crc0;
        v4_header[0].crc2 = crc0;
        u_short crct = crc_cal(v4_header[0]);
        th = (u_char)((crct >> 8) & 0x00ff);//保存高8位
        tl = (u_char)(crct & 0x00ff);//保存低8位
        v4_header[0].crc1 = th;
        v4_header[0].crc2 = tl;
        assembleInfo = assembleInfo + packet_ipv4_dis(v4_header[0]);
        //数据
        int start = 14 + 20;
        for(int k = start; k < start + sum; k++)
        {
            if (k % 16 == 0 && k != 0)//一排十六个
                assembleInfo = assembleInfo + "\n";
            int t = *(pkt_data + k);
            QString st =  QString("%1").arg(t,2,16,QLatin1Char('0'));
            assembleInfo = assembleInfo + st + " ";
        }
        assembleInfo = assembleInfo + "\n";
        ui->assembleInfo->setText(assembleInfo);
    }
    else
    {
        //ipv6 不存在这两种攻击,直接组装
        assembleInfo = "ipv6数据包数据流：\n";
        //帧头
        for (int k = 0; k < 14; k++) {
            int t = *(pkt_data + k);
            QString st =  QString("%1").arg(t,2,16,QLatin1Char('0'));
            assembleInfo = assembleInfo + st + " ";
        }

        //ip数据包头,长度重新计算
        //长度
        int lt = 0;
        for(int i = 0; i < split_n; i++)
        {
            u_short ltt = char2short(v6_header[i].pl1, v6_header[i].pl2);
            lt += ltt;
        }
        u_char th,tl;
        th = (u_char)((lt >> 8) & 0x00ff);//保存高8位
        tl = (u_char)(lt & 0x00ff);//保存低8位
        v6_header[0].pl1 = th;
        v6_header[0].pl2 = tl;
        assembleInfo = assembleInfo + packet_ipv6_dis(v6_header[0]);
        //数据
        int start = 14 + 40;
        for(int k = start; k < start+lt; k++)
        {
            if (k % 16 == 0 && k != 0)//一排十六个
                assembleInfo = assembleInfo + "\n";
            int t = *(pkt_data + k);
            QString st =  QString("%1").arg(t,2,16,QLatin1Char('0'));
            assembleInfo = assembleInfo + st + " ";
        }
        assembleInfo = assembleInfo + "\n";
        ui->assembleInfo->setText(assembleInfo);
    }
}

void MainWindow::on_TearDrop_clicked()
{
    ui->splitInfo->clear();
    ui->assembleInfo->clear();
    if(packetType == 6){
        warningInfo = "Ipv6不存在TearDrop攻击";
        ui->assembleInfo->setText(warningInfo);
        return;
    }
    //TearDrop攻击
    splitInfo = "";
    //MTU
    QString MTU = ui->mtu->text();
    double mtu = MTU.toDouble();
    //IP分组总数据长度
    double ip_data_length = packetLength - 14 - 20;
    if(ip_data_length + 20 <= mtu || mtu <= 20)
    {
        warningInfo = "不可再分，请调整MTU数值";
        ui->warningText->setText(warningInfo);
        return;
    }
    //每帧可承载数据
    double max_data = floor((mtu-20)/8)*8;
    //分片数
    split_n = ceil(ip_data_length/max_data);
    //每片偏移量
    int ip_fo = max_data / 8;
    //开始分片
    for(int i = 0; i < split_n; i++)
    {
        //直接复制的数据
        v4_header[i].ver_ihl = pheader->ver_ihl;//版本号+首部长度
        v4_header[i].tos = pheader->tos;//服务类型
        v4_header[i].identification1 = pheader->identification1;//标识
        v4_header[i].identification2 = pheader->identification2;
        v4_header[i].proto = pheader->proto;//上层协议
        v4_header[i].saddr = pheader->saddr;//源IP地址
        v4_header[i].daddr = pheader->daddr;//目的IP地址
        //待处理的数据
        //标志位+片偏移
        u_char flags_fo1t,flags_fo2t;
        u_char flags;
        if(i != split_n - 1){//不是最后一片
            //DF=0,MF=1
            flags = 0x00 | 0x01;
        }
        else{//最后一片
            //DF=0,MF=0
            flags = 0x00 | 0x00;
        }
        //拼接flags_fo1t
        flags_fo1t = flags << 5;//标志位左移5位，到最终位置
        u_short fot = i * ip_fo;//偏移量
        fot = fot & 0x1fff;//除低13位外清零
        fot = (fot >> 8) & 0x001f;//保留13位中的高5位
        flags_fo1t = flags_fo1t | (u_char)fot;//将这5位保存
        //拼接flags_fo2t
        fot = i * ip_fo;
        fot = fot & 0x00ff;//除低8位外清零
        flags_fo2t = (u_char)fot;//保存这8位
        //保存
        v4_header[i].flags_fo1 = flags_fo1t;
        v4_header[i].flags_fo2 = flags_fo2t;

        //ttl
        v4_header[i].ttl = pheader->ttl - 1;

        //总长
        u_short tlent;
        if(i != split_n - 1){//不是最后一片
            tlent = 20 + ip_fo * 8;//总长度
        }
        else{
            tlent = 20 + ip_data_length - ip_fo * 8 * (split_n - 1);
        }
        v4_header[i].tlen1 = (u_char)((tlent >> 8) & 0x00ff);//保存高8位
        v4_header[i].tlen2 = (u_char)(tlent & 0x00ff);//保存低8位
        //首部校验和
        u_short crct = crc_cal(v4_header[i]);
        u_short crcth = (crct >> 8) & 0x00ff;//高8位
        u_short crctl = crct * 0x00ff;
        v4_header[i].crc1 = (u_char)crcth;
        v4_header[i].crc2 = (u_char)crctl;
        //更改偏移量
        if(i == 1)
        {
            v4_header[i].flags_fo1 = 0x29;
            v4_header[i].flags_fo2 = 0x69;
        }

        //输出
        splitInfo = splitInfo + "-----------------第" + QString::number(i+1,10) + "片-----------------\n";
        //帧头
        splitInfo = splitInfo + "帧头：\n";
        for (int k = 0; k < 14; k++) {
            int t = *(pkt_data + k);
            QString st =  QString("%1").arg(t,2,16,QLatin1Char('0'));
            splitInfo = splitInfo + st + " ";
        }
        splitInfo = splitInfo + "\n";
        //ip头
        splitInfo = splitInfo + "IP头：\n";
        splitInfo = splitInfo + packet_ipv4_dis(v4_header[i],1) + "\n";
        //IP报数据
        splitInfo = splitInfo + "数据：\n";
        int start = 34 + i*ip_fo*8;
        for (int k = start; k < start+tlent-20; k++) {
            int t = *(pkt_data + k);
            QString st =  QString("%1").arg(t,2,16,QLatin1Char('0'));
            splitInfo = splitInfo + st + " ";
        }
        splitInfo = splitInfo + "\n";

        //解析
        splitInfo = splitInfo + "数据包长度：\t" + QString::number(tlent,10) + "\n";
        splitInfo = splitInfo + "标识：\t\t" + QString("%1").arg(v4_header[i].identification1,2,16,QLatin1Char('0')) + QString("%1").arg(v4_header[i].identification2,2,16,QLatin1Char('0')) + "\n";
        splitInfo = splitInfo + "DF、MF：\t\t" + QString("%1").arg(flags,2,2,QLatin1Char('0')) + "\n";
        u_short p1 = char2short(v4_header[i].flags_fo1, v4_header[i].flags_fo2);
        p1 = p1 & 0x1fff;
        splitInfo = splitInfo + "偏移量：\t\t" + QString::number(p1,10) + "\n";
        ui->splitInfo->setText(splitInfo);
    }
}


void MainWindow::on_DeathOfPing_clicked()
{
    ui->splitInfo->clear();
    ui->assembleInfo->clear();
    if(packetType == 6){
        warningInfo = "Ipv6不存在Death of Ping攻击";
        ui->assembleInfo->setText(warningInfo);
        return;
    }
    //Death of Ping 攻击
    splitInfo = "";
    //MTU
    QString MTU = ui->mtu->text();
    double mtu = MTU.toDouble();
    //IP分组总数据长度
    double ip_data_length = packetLength - 14 - 20;
    if(ip_data_length + 20 <= mtu || mtu <= 20)
    {
        warningInfo = "不可再分，请调整MTU数值";
        ui->warningText->setText(warningInfo);
        return;
    }
    //每帧可承载数据
    double max_data = floor((mtu-20)/8)*8;
    //分片数
    split_n = ceil(ip_data_length/max_data);
    //每片偏移量
    int ip_fo = max_data / 8;
    //开始分片
    for(int i = 0; i < split_n; i++)
    {
        //直接复制的数据
        v4_header[i].ver_ihl = pheader->ver_ihl;//版本号+首部长度
        v4_header[i].tos = pheader->tos;//服务类型
        v4_header[i].identification1 = pheader->identification1;//标识
        v4_header[i].identification2 = pheader->identification2;
        v4_header[i].proto = pheader->proto;//上层协议
        v4_header[i].saddr = pheader->saddr;//源IP地址
        v4_header[i].daddr = pheader->daddr;//目的IP地址
        //待处理的数据
        //标志位+片偏移
        u_char flags_fo1t,flags_fo2t;
        u_char flags;
        if(i != split_n - 1){//不是最后一片
            //DF=0,MF=1
            flags = 0x00 | 0x01;
        }
        else{//最后一片
            //DF=0,MF=0
            flags = 0x00 | 0x00;
        }
        //拼接flags_fo1t
        flags_fo1t = flags << 5;//标志位左移5位，到最终位置
        u_short fot = i * ip_fo;//偏移量
        fot = fot & 0x1fff;//除低13位外清零
        fot = (fot >> 8) & 0x001f;//保留13位中的高5位
        flags_fo1t = flags_fo1t | (u_char)fot;//将这5位保存
        //拼接flags_fo2t
        fot = i * ip_fo;
        fot = fot & 0x00ff;//除低8位外清零
        flags_fo2t = (u_char)fot;//保存这8位
        //保存
        v4_header[i].flags_fo1 = flags_fo1t;
        v4_header[i].flags_fo2 = flags_fo2t;

        //ttl
        v4_header[i].ttl = pheader->ttl - 1;

        //总长
        u_short tlent;
        if(i != split_n - 1){//不是最后一片
            tlent = 20 + ip_fo * 8;//总长度
        }
        else{
            tlent = 20 + ip_data_length - ip_fo * 8 * (split_n - 1);
        }
        v4_header[i].tlen1 = (u_char)((tlent >> 8) & 0x00ff);//保存高8位
        v4_header[i].tlen2 = (u_char)(tlent & 0x00ff);//保存低8位
        //首部校验和
        u_short crct = crc_cal(v4_header[i]);
        u_short crcth = (crct >> 8) & 0x00ff;//高8位
        u_short crctl = crct * 0x00ff;
        v4_header[i].crc1 = (u_char)crcth;
        v4_header[i].crc2 = (u_char)crctl;
        //更改长度
        if(i == 0 || i == 1)
        {
            v4_header[i].tlen1 = 0xff;
            v4_header[i].tlen1 = 0xff;
        }

        //输出
        splitInfo = splitInfo + "-----------------第" + QString::number(i+1,10) + "片-----------------\n";
        splitInfo = splitInfo + "帧头：\n";
        //帧头
        for (int k = 0; k < 14; k++) {
            int t = *(pkt_data + k);
            QString st =  QString("%1").arg(t,2,16,QLatin1Char('0'));
            splitInfo = splitInfo + st + " ";
        }
        splitInfo = splitInfo + "\n";
        //ip头
        splitInfo = splitInfo + "IP头：\n";
        splitInfo = splitInfo + packet_ipv4_dis(v4_header[i],1) + "\n";
        //IP报数据
        splitInfo = splitInfo + "数据：\n";
        int start = 34 + i*ip_fo*8;
        for (int k = start; k < start+tlent-20; k++) {
            int t = *(pkt_data + k);
            QString st =  QString("%1").arg(t,2,16,QLatin1Char('0'));
            splitInfo = splitInfo + st + " ";
        }
        splitInfo = splitInfo + "\n";

        //解析
        u_short l1 = char2short(v4_header[i].tlen1, v4_header[i].tlen2);
        splitInfo = splitInfo + "数据包长度：\t" + QString::number(l1,10) + "\n";
        splitInfo = splitInfo + "标识：\t\t" + QString("%1").arg(v4_header[i].identification1,2,16,QLatin1Char('0')) + QString("%1").arg(v4_header[i].identification2,2,16,QLatin1Char('0')) + "\n";
        splitInfo = splitInfo + "DF、MF：\t\t" + QString("%1").arg(flags,2,2,QLatin1Char('0')) + "\n";
        u_short p1 = char2short(v4_header[i].flags_fo1, v4_header[i].flags_fo2);
        p1 = p1 & 0x1fff;
        splitInfo = splitInfo + "偏移量：\t\t" + QString::number(p1,10) + "\n";
        ui->splitInfo->setText(splitInfo);
    }
}
