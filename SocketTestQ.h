#ifndef SOCKETTESTQ_H
#define SOCKETTESTQ_H

#include <QtGui>
#include <QtNetwork>
#include <QtWidgets>
#include <QSslSocket>

#include "csslserver.h"
#include "tcpportlist.h"
#include "udpportlist.h"
//#include <QMainWindow>
#include <QDebug>
#include <QtSerialPort/QSerialPort>
#include <QtSerialPort/QSerialPortInfo>
#include <string>
#include <string.h>
#include <QPointF>
#include <QDateTime>
//#include <ChString.h>

#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonParseError>
#include <QJsonValue>
#include <QFile>
#include <QDir>


#include "qcustomplot.h"
namespace Ui {
class SocketTestQ;
}

class SocketTestQ : public QWidget
{
    Q_OBJECT

public:
    explicit SocketTestQ(QWidget *parent = 0);
    ~SocketTestQ();

    static QSsl::SslProtocol             s_eSSLProtocol;
    static QSslSocket::PeerVerifyMode    s_eSSLVerifyMode;
    static QString                       s_qstrCertFile;
    static QString                       s_qstrKeyFile; // musn't require a passphrase

private slots:
    // Client
    void on_uiClientConnectBtn_clicked();
    void on_uiClientSendMsgBtn_clicked();
    void on_uiClientMsg_returnPressed();
    void ClientReceivedData();
    void ClientConnected();
    void ClientDisconnected();
    void SocketError(QAbstractSocket::SocketError error);
    void ClientOpenFileNameDialog();
    void ClientSaveLogFile();
    void ClientClearLogFile();
    void ClientSendFile();
    void CheckSSLSupport();
    void SocketEncrypted();
    void SslErrors(const QList<QSslError>& listErrors);

    // Server
    void ServerListen();
    void NewClient();
    void ServerReceivedData();
    void ServerSendMsg();
    void ClientDisconnect(); // client disconnection
    void DisconnectClient();  // server kicks client
    void ServerOpenFileNameDialog();
    void ServerSaveLogFile();
    void ServerClearLogFile();
    void ServerSendFile();
    void WarnHex();
    void CheckSSLServerSetup();
    void PrivateKeyDialog();
    void CertDialog();

    void ShowTCPPortList();
    void ShowUDPPortList();

    // UDP
    void UDPListen();
    void UDPSendMsg();
    void UDPReceivedData();
    void UDPOpenFileNameDialog();
    void UDPSendFile();
    void UDPSaveLogFile();
    void UDPClearLogFile();

    //serial
    void on_clearButton_clicked();
    void on_sendButton_clicked();
    void on_openButton_clicked();
    void Read_Data();
    void appendArray(QByteArray data_hand);

    //plot
    void test_plot(QCustomPlot *customPlot);
    //hex to byte array ...etc
    QByteArray getByteArray(QString str);
    QString byteArrayToHexString(QString str);
    QByteArray hexStringToByte(QString hex);
    int bytesToInt(QByteArray bytes);
// communication with CSSLServer
    void on_pushButton_clicked();

    void on_pushButton_2_clicked();
    QString hexToAscall(QString);

    void on_pushButton_3_clicked();

    void on_pushButton_4_clicked();

    void on_pushButton_5_clicked();

    void on_pushButton_6_clicked();

    void on_pushButton_7_clicked();

    void on_pushButton_8_clicked();

    void slotReadData();

    void on_camButton_clicked();

    void on_dataButton_clicked();

    void on_lowSpeedButton_clicked();

    void on_highSpeedButton_clicked();

    void on_SaveButton_clicked();

    void on_FORWARD_BTN_clicked();

    void on_BACK_BTN_clicked();

    void on_StopButton_clicked();

    void on_DATAREAD_clicked();

public slots:
    void ProcessSSLReceivedData(QByteArray SSLByteArray);
    void onSSLClientDisconnected();
    void onNewSSLClient(QSslSocket*);

signals:
    void SendSSLData(const QByteArray&);
    void DisconnectSSLClient();

private:
    Ui::SocketTestQ *ui;
    TCPPortList m_TCPPortList;
    UDPPortList m_UDPPortList;
    //serial
    QSerialPort *serial;
    // Used by Server
    bool        m_bSecureServer;
    QTcpServer* m_Server;
    CSSLServer* m_pSecureServer;
    QTcpSocket* m_ClientSocket;
    //QHash<QTcpSocket*,QByteArray*> m_ClientSockets; // for a future version ;) a client list will be dynamically created
    QByteArray* m_ServerByteArray;

    // Used by Client
    bool        m_bSecure;
    QString     m_qstrCipher;
    QSslSocket* m_ServerSocket; // QSslSocket can behave as a normal QTcpSocket with no overhead
    QByteArray* m_ClientByteArray;

    // Used by UDP
    QUdpSocket* m_UDPSocket;
    QByteArray* m_UDPByteArray;

    //bool for uid and anti
    //int count = 0;
    bool click_uid = false;
    bool click_anti = false;
    bool click_sqa = false;
    QString str2 = "";
    double getNow();

    int refreshTimer;//刷新图像的定时器
    int sampleTimer;//模拟采样的定时器
    double tLast;
    QPointF newPoint;
    QPointF lastPoint;
    int cnt;

    //传输bmp图象
    QByteArray byteArray;
    QPixmap pixmap;
    QMatrix matrix;

    //协议发送
    //uint8_t t=0x30;
    QByteArray ctrl[5]={"FA","00","00","2C","FB"};
    //QString ctrl[5]={"250","0","0","0","251"};
    //帧头0xFA 模式 速度（低八位 高八位）帧尾0xFB
    int hex2Int(QChar num);
    //传输标志
    int mode=0;

    //json保存
    // 使用QJsonObject对象插入键值对。
    QJsonObject jsonObject;
    QJsonObject jsonSave;
    QJsonArray jsonArray;
    long long int num;
    //select uid and anti
    //16 to 10
    static char ConvertHexChar(char ch)
    {
      if((ch >= '0') && (ch <= '9'))
          return ch-0x30;
     else if((ch >= 'A') && (ch <= 'F'))
       return ch-'A'+10;
     else if((ch >= 'a') && (ch <= 'f'))
       return ch-'a'+10;
      else return (-1);
    }

    static QByteArray QString2Hex(QString str)
    {
      QByteArray senddata;
    int hexdata,lowhexdata;
      int hexdatalen = 0;
           int len = str.length();
     senddata.resize(len/2);
       char lstr,hstr;
     for(int i=0; i<len; )
     {
        hstr=str[i].toLatin1();
       if(hstr == ' ')
       {
         i++;
         continue;
       }
       i++;
       if(i >= len)
           break;
       lstr = str[i].toLatin1();
        hexdata = ConvertHexChar(hstr);
       lowhexdata = ConvertHexChar(lstr);
        if((hexdata == 16) || (lowhexdata == 16))
          break;
       else
         hexdata = hexdata*16+lowhexdata;
        i++;
        senddata[hexdatalen] = (char)hexdata;
        hexdatalen++;
     }
      senddata.resize(hexdatalen);
        return senddata;
    }
protected:

    void timerEvent(QTimerEvent *event);
};

#endif // SOCKETTESTQ_H
