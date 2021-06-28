#include "SocketTestQ.h"
#include "ui_SocketTestQ.h"
#include <qdebug.h>
#include <QtSerialPort/QSerialPort>
#include <QtSerialPort/QSerialPortInfo>
#include <QtGui/QApplicationStateChangeEvent>
#define MAX_HOSTNAME_LENGTH     255

//used for stm32 type-a card, you can change it to your card command
static const char sel_uid[] = {0x26,0x3f,0x3b};
static const char sel_anti[] = {0x20,0x20,0x3f,0x3b};
static const char sel_sqa[] = {0x20,0x70,0x3f,0x3b};

//static const char sel_anti[] = {0x93,0x20,0x3f,0x3b};
//static const char sel_sqa[] = {0x93,0x70,0x3f,0x3b};

#define my_delete(x) {delete x; x = 0;}


QSsl::SslProtocol             SocketTestQ::s_eSSLProtocol = QSsl::AnyProtocol;
QSslSocket::PeerVerifyMode    SocketTestQ::s_eSSLVerifyMode = QSslSocket::VerifyNone;
QString                       SocketTestQ::s_qstrCertFile;
QString                       SocketTestQ::s_qstrKeyFile;
QByteArray RecData;
int temp;
int i=0;
SocketTestQ::SocketTestQ(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::SocketTestQ),
    m_bSecure(false), // client
    m_bSecureServer(false)
{
    // ************** Miscellaneous
    // **************
    ui->setupUi(this);
    cnt = 0;
    QSharedPointer<QCPAxisTickerDateTime> dateTicker(new QCPAxisTickerDateTime);//日期做X轴
    dateTicker->setDateTimeFormat("hh:mm:ss.zzz\nyyyy-MM-dd");//日期格式(可参考QDateTime::fromString()函数)
    ui->plot->xAxis->setTicker(dateTicker);//设置X轴为时间轴
    ui->plot->xAxis->setTickLabels(true);//显示刻度标签

    ui->plot->addGraph(ui->plot->xAxis, ui->plot->yAxis);

    ui->plot->setInteractions(QCP::iRangeDrag //可平移
                                | QCP::iRangeZoom //可滚轮缩放
                                | QCP::iSelectLegend );//可选中图例
    ui->plot->yAxis->setRange(-1.5, 1.5);


    refreshTimer = startTimer(30, Qt::CoarseTimer);
    sampleTimer = startTimer(1000, Qt::CoarseTimer);

    tLast = getNow();

    lastPoint.setX(getNow());
    lastPoint.setY(qSin(lastPoint.x()));
    setFixedSize(geometry().width(),geometry().height());
    //setWindowTitle(tr("SocketTestQ v 1.0.0"));

    // ************** Server
    // **************
    m_Server = new QTcpServer(this);
    m_pSecureServer = new CSSLServer(this);
    m_ClientSocket = 0;
    m_ServerByteArray = new QByteArray();

    // Connection between signals and slots of buttons
    connect(ui->uiServerListenBtn, SIGNAL(clicked()), this, SLOT(ServerListen()));
    connect(ui->uiServerPortListBtn, SIGNAL(clicked()), this, SLOT(ShowTCPPortList()));

    connect(ui->uiServerSendMsgBtn, SIGNAL(clicked()), this, SLOT(ServerSendMsg()));
    connect(ui->uiServerBrowseBtn, SIGNAL(clicked()), this, SLOT(ServerOpenFileNameDialog()));
    connect(ui->uiServerSendFileBtn, SIGNAL(clicked()), this, SLOT(ServerSendFile()));

    connect(ui->uiServerSaveLogBtn, SIGNAL(clicked()), this, SLOT(ServerSaveLogFile()));
    connect(ui->uiServerClearLogBtn, SIGNAL(clicked()), this, SLOT(ServerClearLogFile()));
    connect(ui->uiServerDisconnectBtn, SIGNAL(clicked()), this, SLOT(DisconnectClient()));
    connect(ui->uiServerRadioHex, SIGNAL(clicked()), this, SLOT(WarnHex()));
    connect(ui->uiServerSecure, SIGNAL(clicked()), this, SLOT(CheckSSLServerSetup()));
    connect(ui->uiBtnLoadKey, SIGNAL(clicked()), this, SLOT(PrivateKeyDialog()));
    connect(ui->uiBtnLoadCert, SIGNAL(clicked()), this, SLOT(CertDialog()));

    // Connection between signals and slots of non-gui elements (network communication)
    connect(m_Server, SIGNAL(newConnection()), this, SLOT(NewClient()));
    // SSL
    connect(this, SIGNAL(DisconnectSSLClient()), m_pSecureServer, SLOT(SSLClientDisconnect()));
    connect(this, SIGNAL(SendSSLData(const QByteArray&)), m_pSecureServer, SLOT(onSSLSendData(const QByteArray&)));

    // ************** Client
    // ************** autoconnect has been used for a few client's widgets
    m_ServerSocket = new QSslSocket(this);
    m_ServerSocket->setPeerVerifyMode(QSslSocket::VerifyNone);
    m_ClientByteArray = new QByteArray();

    // Connection between signals and slots of non-gui elements (network communication)
    connect(m_ServerSocket, SIGNAL(readyRead()), this, SLOT(ClientReceivedData()));
    connect(m_ServerSocket, SIGNAL(connected()), this, SLOT(ClientConnected()));
    connect(m_ServerSocket, SIGNAL(disconnected()), this, SLOT(ClientDisconnected()));
    connect(m_ServerSocket, SIGNAL(error(QAbstractSocket::SocketError)), this, SLOT(SocketError(QAbstractSocket::SocketError)));
    /* used only in Secure Mode */
    connect(m_ServerSocket, SIGNAL(encrypted()), this, SLOT(SocketEncrypted()));
    connect(m_ServerSocket, SIGNAL(sslErrors(const QList<QSslError>&)), this, SLOT(SslErrors(const QList<QSslError>&)));

    // Connection between signals and slots of buttons
    connect(ui->uiClientPortListBtn, SIGNAL(clicked()), this, SLOT(ShowTCPPortList()));
    connect(ui->uiClientRadioHex, SIGNAL(clicked()), this, SLOT(WarnHex()));
    connect(ui->uiClientBrowseBtn, SIGNAL(clicked()), this, SLOT(ClientOpenFileNameDialog()));
    connect(ui->uiClientSendFileBtn, SIGNAL(clicked()), this, SLOT(ClientSendFile()));
    connect(ui->uiClientSaveLogBtn, SIGNAL(clicked()), this, SLOT(ClientSaveLogFile()));
    connect(ui->uiClientClearLogBtn, SIGNAL(clicked()), this, SLOT(ClientClearLogFile()));
    connect(ui->uiClientSecureCheck, SIGNAL(clicked()), this, SLOT(CheckSSLSupport()));

    // ************** UDP
    // **************
    m_UDPSocket = new QUdpSocket(this);
    m_UDPByteArray = new QByteArray();

    // Connection between signals and slots of non-gui elements (network communication)
    connect(m_UDPSocket, SIGNAL(readyRead()), this, SLOT(UDPReceivedData()));

    // Connection between signals and slots of buttons
    connect(ui->uiUdpServerListenBtn, SIGNAL(clicked()), this, SLOT(UDPListen()));
    connect(ui->uiUdpSendMsgBtn, SIGNAL(clicked()), this, SLOT(UDPSendMsg()));
    connect(ui->uiUdpBrowseBtn, SIGNAL(clicked()), this, SLOT(UDPOpenFileNameDialog()));
    connect(ui->uiUdpSendFileBtn, SIGNAL(clicked()), this, SLOT(UDPSendFile()));
    connect(ui->uiUdpSaveLogBtn, SIGNAL(clicked()), this, SLOT(UDPSaveLogFile()));
    connect(ui->uiUdpClearLogBtn, SIGNAL(clicked()), this, SLOT(UDPClearLogFile()));
    connect(ui->uiUdpServerPortListBtn, SIGNAL(clicked()), this, SLOT(ShowUDPPortList()));
    connect(ui->uiUdpClientPortListBtn, SIGNAL(clicked()), this, SLOT(ShowUDPPortList()));
    connect(ui->uiUdpRadioHex, SIGNAL(clicked()), this, SLOT(WarnHex()));


    //server
    //查找可用的串口
    foreach(const QSerialPortInfo &info, QSerialPortInfo::availablePorts())
    {
        QSerialPort serial;
        serial.setPort(info);
        if(serial.open(QIODevice::ReadWrite))
        {
            ui->PortBox->addItem(serial.portName());
            serial.close();
        }
        qDebug() << serial.portName();
    }
    //设置波特率下拉菜单默认显示第三项
    ui->BaudBox->setCurrentIndex(5);
    //关闭发送按钮的使能
    ui->sendButton->setEnabled(false);
    qDebug() << tr("界面设定成功");
}

// ************** Server
// **************

void SocketTestQ::ServerListen()
{
    ui->uiServerSecure->setEnabled(false);
    m_bSecureServer = (ui->uiServerSecure->isChecked()) ? true : false;
    QTcpServer* pCurrentServer = (m_bSecureServer) ? m_pSecureServer : m_Server;

    if(pCurrentServer->isListening())
    {
        pCurrentServer->close();
        ui->uiServerListenBtn->setText( tr("Start Listening") );
        (!m_bSecureServer) ? ui->uiServerLog->append(tr("Server stopped"))
                           : ui->uiServerLog->append(tr("SSL Server stopped"));
        ui->uiServerSecure->setEnabled(true);
        return;
    }

    if((ui->uiServerIP->text()).length() <= MAX_HOSTNAME_LENGTH )
    {
        QHostAddress ServerAddress(ui->uiServerIP->text()); // if this ctor is not explicit, we can put the text directly on listen()

        if ( !pCurrentServer->listen(ServerAddress, ui->uiServerPort->value() ) )
        {
            QMessageBox::critical(this, (m_bSecureServer) ? tr("Secure Server Error") : tr("Server Error"),
                                        tr("Server couldn't start. Reason :<br />") + pCurrentServer->errorString());
            ui->uiServerSecure->setEnabled(true);
        }
        else
        {
            ui->uiServerListenBtn->setText( tr("Stop Listening") );
            ui->uiServerLog->append((m_bSecureServer) ? tr("Secure Server Started\r\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~") :
                                                        tr("Server Started\r\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"));
        }
    }
    else
    {
        QMessageBox::critical(this, (m_bSecureServer) ? tr("Secure TCP Server Error") : tr("TCP Server Error"),
                                    tr("IP address / hostname is too long !"));
        ui->uiServerSecure->setEnabled(true);
    }
}

void SocketTestQ::NewClient()
{
    if(!m_ClientSocket && m_Server->hasPendingConnections() ) // we accept only one client in version 1.0.0
    {
        m_ClientSocket = m_Server->nextPendingConnection();

        connect(m_ClientSocket, SIGNAL(readyRead()), this, SLOT(ServerReceivedData())); // append bytes in Log
        connect(m_ClientSocket, SIGNAL(disconnected()), this, SLOT(ClientDisconnect()));

        ui->uiServerGroupBoxConnection->setTitle( tr("Connected Client : < ") + (m_ClientSocket->peerAddress()).toString() +tr(" >") );

        //ui->uiServerLog->append(tr("New Client: ") + m_ClientSocket->peerName()); // empty
        ui->uiServerLog->append(tr("New Client addr: ") + (m_ClientSocket->peerAddress()).toString());

        ui->uiServerSendMsgBtn->setEnabled(true);
        ui->uiServerSendFileBtn->setEnabled(true);
        ui->uiServerBrowseBtn->setEnabled(true);
        ui->uiServerDisconnectBtn->setEnabled(true);
    }
}

void SocketTestQ::ClientDisconnect()
{
    QTcpSocket *socket = qobject_cast<QTcpSocket *>(sender()); // similar to dynamic_cast
    if (socket == 0)
        return;

    socket->deleteLater();
    ui->uiServerSendMsgBtn->setEnabled(false);
    ui->uiServerSendFileBtn->setEnabled(false);
    ui->uiServerBrowseBtn->setEnabled(false);
    ui->uiServerDisconnectBtn->setEnabled(false);
    m_ClientSocket = 0;
    ui->uiServerGroupBoxConnection->setTitle( tr("Connected Client : < NONE >") );
    ui->uiServerLog->append(tr("Client closed conection."));
}

void SocketTestQ::DisconnectClient()
{
    if(!m_bSecureServer)
    {
        if (m_ClientSocket)
        {
            m_ClientSocket->deleteLater();
            ui->uiServerSendMsgBtn->setEnabled(false);
            ui->uiServerSendFileBtn->setEnabled(false);
            ui->uiServerBrowseBtn->setEnabled(false);
            ui->uiServerDisconnectBtn->setEnabled(false);
            m_ClientSocket = 0;
            ui->uiServerGroupBoxConnection->setTitle( tr("Connected Client : < NONE >") );
            ui->uiServerLog->append(tr("Server closed client connection."));
        }
        return;
    }

    // SSL
    emit DisconnectSSLClient();
}

// TODO : store rcvd data in a file for next version
void SocketTestQ::ServerReceivedData()
{
    QTcpSocket *socket = qobject_cast<QTcpSocket *>(sender()); // which client has sent data
    if (socket == 0)
        return;

    while (socket->bytesAvailable() > 0)
    {
        m_ServerByteArray->append(socket->readAll());
        if(ui->uiServerRadioHex->isChecked())
        {
            ui->uiServerLog->append(QString(m_ServerByteArray->toHex())); // TODO : make it more pretty to the user (tpUpper+separated symbols)
        }
        else
        {
            ui->uiServerLog->append(QString(*m_ServerByteArray));
        }
        m_ServerByteArray->remove(0, m_ServerByteArray->size() );
    }
}

void SocketTestQ::WarnHex()
{
    QMessageBox::warning(this, tr("Hex mode"), tr("Experimental feature. Please send me your suggestion."));
}

void SocketTestQ::ServerSendMsg()
{
    QByteArray packet;

    if (ui->uiServerRadioHex->isChecked())
    {
        bool bNonHexSymbol = false;
        QString strTmp = ui->uiServerMsg->text().toUpper();

        for(int c=0; c < strTmp.toUtf8().length(); c++)
        {
            if (strTmp.toUtf8().at(c) >= '0' && strTmp.toUtf8().at(c) <= '9')
            {
                packet.append( (strTmp.toUtf8().at(c) - 48) );
                qDebug() << (strTmp.toUtf8().at(c) - 48);
            }
            else if(strTmp.toUtf8().at(c) >= 'A' && strTmp.toUtf8().at(c) <= 'F' )
            {
                packet.append( (strTmp.toUtf8().at(c) - 55) );
                qDebug() << (strTmp.toUtf8().at(c) - 55);
            }
            else
                bNonHexSymbol = true;
        }
        if (bNonHexSymbol)
            QMessageBox::warning(this, tr("Non Hexadecimal symbols"), tr("Detected non hexadecimal symbols in the message. They will not be sent."));
    }
    else
    {
        for(int c=0; c < ui->uiServerMsg->text().toUtf8().length(); c++)
            packet.append( ui->uiServerMsg->text().toUtf8().at(c) );

        if (ui->uiServerRadioNull->isChecked())
            packet.append( (char)'\0' ); // NULL
        else if (ui->uiServerRadioCRLF->isChecked())
        {
            packet.append( (char)'\r' ); // CR
            packet.append( (char)'\n' ); // LF
        }
    }

    if (!m_bSecureServer)
        m_ClientSocket->write(packet);
    else
        emit SendSSLData(packet);

    (!m_bSecureServer) ? ui->uiServerLog->append("[=>] : " + ui->uiServerMsg->text())
                       : ui->uiServerLog->append("[Encrypted =>] : " + ui->uiServerMsg->text());
    ui->uiServerMsg->setText("");
}

void SocketTestQ::ServerOpenFileNameDialog()
{
    ui->uiServerFile->setText(QFileDialog::getOpenFileName(this, tr("Open a file"), QString(), "*.*"));
}

void SocketTestQ::ServerSaveLogFile()
{
    QFile file(QFileDialog::getSaveFileName(this, tr("Save log file"), QString(), "Text files (*.txt);;*.*"));

    // Trying to open in WriteOnly and Text mode
    if(!file.open(QFile::WriteOnly |
                  QFile::Text))
    {
        QMessageBox::critical(this, tr("File Error"), tr("Could not open file for writing !"));
        return;
    }

    // To write text, we use operator<<(),
    // which is overloaded to take
    // a QTextStream on the left
    // and data types (including QString) on the right

    QTextStream out(&file);
    out << ui->uiServerLog->toPlainText(); // or file.write(byteArray);
    file.flush();
    file.close();
}

void SocketTestQ::ServerClearLogFile()
{
    ui->uiServerLog->clear();
}

void SocketTestQ::ShowTCPPortList()
{
    m_TCPPortList.show();
}

void SocketTestQ::ShowUDPPortList()
{
    m_UDPPortList.show();
}

void SocketTestQ::ServerSendFile()
{
    if(ui->uiServerFile->text().isEmpty())
        QMessageBox::critical(this, tr("File Error"), tr("Enter a file path !"));
    else
    {
        QFile file(ui->uiServerFile->text());
        if(!file.open(QFile::ReadOnly))
        {
            QMessageBox::critical(this, tr("File Error"), tr("Could not open the file for reading."));
            return;
        }

        QByteArray packet = file.readAll();

        if (!m_bSecureServer)
            m_ClientSocket->write(packet);
        else
            emit SendSSLData(packet);

        file.close();
        (!m_bSecureServer) ? ui->uiServerLog->append("[=>] File was sent to connected client.")
                           : ui->uiServerLog->append("[=>] File was sent to connected SSL client.");
    }
}

/******** Client ********/

// Connection attempt to a server
void SocketTestQ::on_uiClientConnectBtn_clicked()
{
    //bool bUnconnected = !m_ServerSocket || m_ServerSocket->state() == QAbstractSocket::UnconnectedState;
    bool bConnected = m_ServerSocket->state() == QAbstractSocket::ConnectedState; // no need to check for nullptr.
    if (bConnected) // m_ServerSocket->isOpen()
    {
        m_ServerSocket->close();
        return;
    }

    m_bSecure = (ui->uiClientSecureCheck->isChecked()) ? true : false;

    ui->uiClientLog->append(tr("<em>Attempting to connect...</em>"));

    m_ServerSocket->abort(); // disable previous connections if they exist

    if (m_bSecure)
    {
        m_ServerSocket->setProtocol(s_eSSLProtocol);
        m_ServerSocket->setPeerVerifyMode(s_eSSLVerifyMode);

        /* Set the certificate and private key. */
        m_ServerSocket->setLocalCertificate(s_qstrCertFile);
        m_ServerSocket->setPrivateKey(s_qstrKeyFile);

        /* connection to the requested SSL/TLS server */
        m_ServerSocket->connectToHostEncrypted(ui->uiClientDstIP->text(), ui->uiClientDstPort->value());
    }
    else
    {
        /* connection to the requested unencrypted server */
        m_ServerSocket->connectToHost(ui->uiClientDstIP->text(), ui->uiClientDstPort->value());
    }
}

void SocketTestQ::SocketEncrypted()
{
    if (!m_bSecure)
        return;

    QSslSocket* pSocket = qobject_cast<QSslSocket*>(m_ServerSocket);
    if (pSocket == 0)
        return; // or might have disconnected already

    // get the peer's certificate
    //QSslCertificate certCli = pSocket->peerCertificate();

    QSslCipher ciph = pSocket->sessionCipher();
    m_qstrCipher = QString("%1, %2 (%3/%4)").arg(ciph.authenticationMethod())
                     .arg(ciph.name()).arg(ciph.usedBits()).arg(ciph.supportedBits());

    ui->uiClientGroupBoxConnection->setTitle( tr("Connected To < ") + (m_ServerSocket->peerAddress()).toString()
                                              + ((m_bSecure) ? (tr(" > Cipher : ") + m_qstrCipher) : tr(" > Unencrypted")) );
}

void SocketTestQ::SslErrors(const QList<QSslError>& listErrors)
{
    listErrors; // unreferenced_parameter

    m_ServerSocket->ignoreSslErrors();
}

// Sending msg to server
void SocketTestQ::on_uiClientSendMsgBtn_clicked()
{
    QByteArray packet;

    if (ui->uiClientRadioHex->isChecked())
    {
        bool bNonHexSymbol = false;
        QString strTmp = ui->uiClientMsg->text().toUpper();

        for(int c=0; c < strTmp.toUtf8().length(); c++)
        {
            if (strTmp.toUtf8().at(c) >= '0' && strTmp.toUtf8().at(c) <= '9')
            {
                packet.append( (strTmp.toUtf8().at(c) - 48) );
                qDebug() << (strTmp.toUtf8().at(c) - 48);
            }
            else if(strTmp.toUtf8().at(c) >= 'A' && strTmp.toUtf8().at(c) <= 'F' )
            {
                packet.append( (strTmp.toUtf8().at(c) - 55) );
                qDebug() << (strTmp.toUtf8().at(c) - 55);
            }
            else
                bNonHexSymbol = true;
        }
        if (bNonHexSymbol)
            QMessageBox::warning(this, tr("Non Hexadecimal symbols"), tr("Detected non hexadecimal symbols in the message. They will not be sent."));
    }
    else
    {
        for(int c=0; c < ui->uiClientMsg->text().toUtf8().length(); c++)
            packet.append( ui->uiClientMsg->text().toUtf8().at(c) );

        if (ui->uiClientRadioNull->isChecked())
            packet.append( (char)'\0' ); // NULL
        else if (ui->uiClientRadioCRLF->isChecked())
        {
            packet.append( (char)'\r' ); // CR
            packet.append( (char)'\n' ); // LF
        }
    }

    m_ServerSocket->write(packet);

    ui->uiClientLog->append("[=>] : " + ui->uiClientMsg->text());
    ui->uiClientMsg->clear();
    ui->uiClientMsg->setFocus(); // set the focus inside it
}

// Pressing "Enter" has the same effect than clicking on "Send" button
void SocketTestQ::on_uiClientMsg_returnPressed()
{
    on_uiClientSendMsgBtn_clicked();
}

// packet received or a sub-packet
void SocketTestQ::ClientReceivedData()
{
    QTcpSocket *socket = qobject_cast<QTcpSocket *>(sender()); // which client has sent data
    if (socket == 0)
        return;

    while (socket->bytesAvailable() > 0)
    {
        m_ClientByteArray->append(socket->readAll());
        if(ui->uiClientRadioHex->isChecked())
        {
            ui->uiClientLog->append(QString(m_ClientByteArray->toHex()));
        }
        else
        {
            ui->uiClientLog->append(QString(*m_ClientByteArray));
        }
        m_ClientByteArray->remove(0, m_ClientByteArray->size() );
    }
}

// this slot gets called when the connection to the remote destination has succeeded.
void SocketTestQ::ClientConnected()
{
    ui->uiClientLog->append(tr("<em>Connected !</em>"));
    ui->uiClientConnectBtn->setText(tr("Disconnect"));
    if (!m_bSecure)
        ui->uiClientGroupBoxConnection->setTitle(tr("Connected To < ") + (m_ServerSocket->peerAddress()).toString() +tr(" >"));
    ui->uiClientSendMsgBtn->setEnabled(true);
    ui->uiClientSendFileBtn->setEnabled(true);
    ui->uiClientBrowseBtn->setEnabled(true);
}

// this slot gets called when the client gets disconnected
void SocketTestQ::ClientDisconnected()
{
    ui->uiClientGroupBoxConnection->setTitle(tr("Connected to < NONE >"));
    ui->uiClientConnectBtn->setText(tr("Connect"));
    ui->uiClientSendMsgBtn->setEnabled(false);
    ui->uiClientSendFileBtn->setEnabled(false);
    ui->uiClientBrowseBtn->setEnabled(false);
}

// this slot gets called when there is a socket related error
void SocketTestQ::SocketError(QAbstractSocket::SocketError error)
{
    switch(error) // On affiche un message diff茅rent selon l'erreur qu'on nous indique
    {
        case QAbstractSocket::HostNotFoundError:
            QMessageBox::critical(this, tr("Opening connection"), tr("Connection refused, server not found, check IP and Port "));
            break;
        case QAbstractSocket::ConnectionRefusedError:
            QMessageBox::critical(this, tr("Opening connection"), tr("Connection refused, server refused the connection, check IP and Port and that server is available"));
            break;
        case QAbstractSocket::RemoteHostClosedError:
            QMessageBox::warning(this, tr("Disconnected"), tr("Server closed the connection "));
            break;
        default:
            QMessageBox::critical(this, tr("Information"), tr("<em>ERROR : ") + m_ServerSocket->errorString() + tr("</em>"));
    }

    ui->uiClientConnectBtn->setText(tr("Connect"));
}

void SocketTestQ::ClientOpenFileNameDialog()
{
    ui->uiClientFile->setText(QFileDialog::getOpenFileName(this, tr("Open a file"), QString(), "*.*"));
}

void SocketTestQ::ClientSaveLogFile()
{
    QFile file(QFileDialog::getSaveFileName(this, tr("Save log file"), QString(), "Text files (*.txt);;*.*"));

    // Trying to open in WriteOnly and Text mode
    if(!file.open(QFile::WriteOnly |
                  QFile::Text))
    {
        QMessageBox::critical(this, tr("File Error"), tr("Could not open file for writing !"));
        return;
    }

    // To write text, we use operator<<(),
    // which is overloaded to take
    // a QTextStream on the left
    // and data types (including QString) on the right

    QTextStream out(&file);
    out << ui->uiClientLog->toPlainText(); // or file.write(byteArray);
    file.flush();
    file.close();
}

void SocketTestQ::ClientClearLogFile()
{
    ui->uiClientLog->clear();
}

void SocketTestQ::ClientSendFile()
{
    if(ui->uiClientFile->text().isEmpty())
        QMessageBox::critical(this, tr("File Error"), tr("Enter a file path !"));
    else
    {
        QFile file(ui->uiClientFile->text());
        if(!file.open(QFile::ReadOnly))
        {
            QMessageBox::critical(this, tr("File Error"), tr("Could not open the file for reading."));
            return;
        }

        QByteArray packet = file.readAll();

        m_ServerSocket->write(packet);

        file.close();
        ui->uiClientLog->append("[=>] File was sent to server.");
    }
}

/******** UDP ********/

void SocketTestQ::UDPListen()
{
    if(m_UDPSocket->state() != QAbstractSocket::UnconnectedState)
    {
        m_UDPSocket->close();
        ui->uiUdpServerListenBtn->setText( tr("Start Listening") );
        ui->uiUdpLog->append(tr("UDP Server stopped"));
        return;
    }

    if((ui->uiServerIP->text()).length() <= MAX_HOSTNAME_LENGTH )
    {
        QHostAddress ServerAddress(ui->uiUdpServerIp->text());

        if ( !m_UDPSocket->bind(ServerAddress,ui->uiUdpServerPort->value()) )
        {
            QMessageBox::critical(this, tr("UDP Server Error"), tr("UDP server couldn't start. Reason :<br />") + m_UDPSocket->errorString());
        }
        else
        {
            ui->uiUdpServerListenBtn->setText( tr("Stop Listening") );
            ui->uiUdpLog->append(tr("Server Started on Port : ") + QString::number(ui->uiUdpServerPort->value()));
        }
    }
    else
    {
        QMessageBox::critical(this, tr("UDP Server Error"), tr("IP address / hostname is too long !"));
    }
}

void SocketTestQ::UDPSendMsg()
{
    QByteArray packet;

    if (ui->uiUdpRadioHex->isChecked())
    {
        bool bNonHexSymbol = false;
        QString strTmp = ui->uiUdpMsg->text().toUpper();

        for(int c=0; c < strTmp.toUtf8().length(); c++)
        {
            if (strTmp.toUtf8().at(c) >= '0' && strTmp.toUtf8().at(c) <= '9')
            {
                packet.append( (strTmp.toUtf8().at(c) - 48) );
                qDebug() << (strTmp.toUtf8().at(c) - 48);
            }
            else if(strTmp.toUtf8().at(c) >= 'A' && strTmp.toUtf8().at(c) <= 'F' )
            {
                packet.append( (strTmp.toUtf8().at(c) - 55) );
                qDebug() << (strTmp.toUtf8().at(c) - 55);
            }
            else
                bNonHexSymbol = true;
        }
        if (bNonHexSymbol)
            QMessageBox::warning(this, tr("Non Hexadecimal symbols"), tr("Detected non hexadecimal symbols in the message. They will not be sent."));
    }
    else
    {
        for(int c=0; c < ui->uiUdpMsg->text().toUtf8().length(); c++)
            packet.append( ui->uiUdpMsg->text().toUtf8().at(c) );

        if (ui->uiUdpRadioNull->isChecked())
            packet.append( (char)'\0' ); // NULL
        else if (ui->uiUdpRadioCRLF->isChecked())
        {
            packet.append( (char)'\r' ); // CR
            packet.append( (char)'\n' ); // LF
        }
    }

    m_UDPSocket->writeDatagram(packet, QHostAddress(ui->uiUdpClientIp->text()), ui->uiUdpClientPort->value());

    ui->uiUdpLog->append("[=>] : " + ui->uiUdpMsg->text());
    ui->uiUdpMsg->clear();
}

void SocketTestQ::UDPSaveLogFile()
{
    QFile file(QFileDialog::getSaveFileName(this, tr("Save log file"), QString(), "Text files (*.txt);;*.*"));

    // Trying to open in WriteOnly and Text mode
    if(!file.open(QFile::WriteOnly |
                  QFile::Text))
    {
        QMessageBox::critical(this, tr("File Error"), tr("Could not open file for writing !"));
        return;
    }

    // To write text, we use operator<<(),
    // which is overloaded to take
    // a QTextStream on the left
    // and data types (including QString) on the right

    QTextStream out(&file);
    out << ui->uiUdpLog->toPlainText(); // or file.write(byteArray);
    file.flush();
    file.close();
}

void SocketTestQ::UDPClearLogFile()
{
    ui->uiUdpLog->clear();
}

void SocketTestQ::UDPOpenFileNameDialog()
{
    ui->uiUdpFile->setText(QFileDialog::getOpenFileName(this, tr("Open a file"), QString(), "*.*"));
}

void SocketTestQ::UDPSendFile()
{
    if(ui->uiUdpFile->text().isEmpty())
        QMessageBox::critical(this, tr("File Error"), tr("Enter a file path !"));
    else
    {
        QFile file(ui->uiUdpFile->text());
        if(!file.open(QFile::ReadOnly))
        {
            QMessageBox::critical(this, tr("File Error"), tr("Could not open the file for reading."));
            return;
        }

        QByteArray packet = file.readAll();

        m_UDPSocket->writeDatagram(packet, QHostAddress(ui->uiUdpClientIp->text()), ui->uiUdpClientPort->value());

        file.close();
        ui->uiUdpLog->append("[=>] File was sent.");
    }
}

void SocketTestQ::UDPReceivedData()
{
    QUdpSocket *socket = qobject_cast<QUdpSocket *>(sender()); // which client has sent data
    if (socket == 0)
        return;

    m_UDPByteArray->resize(socket->pendingDatagramSize());

    QHostAddress sender;
    quint16 senderPort;

    socket->readDatagram(m_UDPByteArray->data(), m_UDPByteArray->size(), &sender, &senderPort);

    if(ui->uiUdpRadioHex->isChecked())
    {
        ui->uiUdpLog->append(QString(m_UDPByteArray->toHex()));
    }
    else
    {
        ui->uiUdpLog->append(QString(*m_UDPByteArray));
    }

    m_UDPByteArray->remove(0, m_UDPByteArray->size() );
}

SocketTestQ::~SocketTestQ()
{
    delete ui;
    delete m_ServerByteArray;
    delete m_Server;
    delete m_ServerSocket;
    delete m_ClientByteArray;
  //  if(serial) delete serial;

}

void SocketTestQ::CheckSSLSupport()
{
    if (!QSslSocket::supportsSsl())
    {
        QMessageBox::information(0, "Secure Socket Client",
                                    "This system does not support OpenSSL.");

        ui->uiClientSecureCheck->setEnabled(false);
        ui->uiClientSecureCheck->setChecked(false);

        return;
    }

    // enryption files are not mandatory for an SSL/TLS client.
    s_qstrKeyFile = ui->uiKeyFileCli->text();
    s_qstrCertFile = ui->uiCertFileCli->text();

    switch (ui->uiCBProtocolCli->currentIndex())
    {
        default:
        case 0:
            s_eSSLProtocol = QSsl::AnyProtocol; // auto: SSLv2, SSLv3, or TLSv1.0
            break;
        case 1: // SSLv2
            s_eSSLProtocol = QSsl::SslV2;
            break;
        case 2: // SSLv3
            s_eSSLProtocol = QSsl::SslV3;
            break;
        case 3: // TLSv1.0
            s_eSSLProtocol = QSsl::TlsV1_0;
            break;
    }

    switch (ui->uiCBVerifyModeCli->currentIndex())
    {
        default:
        case 0:
            s_eSSLVerifyMode = QSslSocket::VerifyNone;
            break;
        case 1:
            s_eSSLVerifyMode = QSslSocket::QueryPeer;
            break;
        case 2:
            s_eSSLVerifyMode = QSslSocket::VerifyPeer;
            break;
        case 3:
            s_eSSLVerifyMode = QSslSocket::AutoVerifyPeer;
            break;
    }
}

void SocketTestQ::CheckSSLServerSetup()
{
    if (!QSslSocket::supportsSsl())
    {
        QMessageBox::information(0, "Secure Socket Server",
                                    "This system does not support OpenSSL.");

        ui->uiServerSecure->setEnabled(false);
        ui->uiServerSecure->setChecked(false);
        return;
    }

    // Check if the required files's paths are indicated and warn user if there's a problem...
    if (ui->uiKeyFile->text().isEmpty())
    {
        QMessageBox::information(0, "Secure Socket Server",
                                    "You didn't indicate private key's file path. Go to SSL Settings.");
        ui->uiServerSecure->setChecked(false);
        return;
    }
    CSSLServer::s_qstrKeyFile = ui->uiKeyFile->text();

    if (ui->uiCertFile->text().isEmpty())
    {
        QMessageBox::information(0, "Secure Socket Server",
                                    "You didn't indicate server's certificate file path. Go to SSL Settings.");
        ui->uiServerSecure->setChecked(false);
        return;
    }
    CSSLServer::s_qstrCertFile = ui->uiCertFile->text();

    switch (ui->uiCBProtocol->currentIndex())
    {
        default:
        case 0:
            /* The socket understands SSLv2, SSLv3, and TLSv1.0.
             * This value is used by QSslSocket only.*/
            CSSLServer::s_eSSLProtocol = QSsl::AnyProtocol;
            break;
        case 1: // SSLv2
            CSSLServer::s_eSSLProtocol = QSsl::SslV2;
            break;
        case 2: // SSLv3
            CSSLServer::s_eSSLProtocol = QSsl::SslV3;
            break;
        case 3: // TLSv1.0
            CSSLServer::s_eSSLProtocol = QSsl::TlsV1_0;
            break;
    }

    switch (ui->uiCBVerifyMode->currentIndex())
    {
        /* QSslSocket will not request a certificate from the peer.
         * You can set this mode if you are not interested in the identity of the other side of the connection.
         * The connection will still be encrypted, and your socket will still send its local certificate
         * to the peer if it's requested.
         */
        default:
        case 0:
            CSSLServer::s_eSSLVerifyMode = QSslSocket::VerifyNone;
            break;

        /* QSslSocket will request a certificate from the peer, but does not require this certificate to be valid.
         * This is useful when you want to display peer certificate details to the user without affecting
         * the actual SSL handshake.
         * This mode is the default for servers.
         */
        case 1:
            CSSLServer::s_eSSLVerifyMode = QSslSocket::QueryPeer;
            break;

        /* QSslSocket will request a certificate from the peer during the SSL handshake phase, and requires
         * that this certificate is valid. On failure, QSslSocket will emit the QSslSocket::sslErrors() signal.
         * This mode is the default for clients.
         */
        case 2:
            CSSLServer::s_eSSLVerifyMode = QSslSocket::VerifyPeer;
            break;

        /* QSslSocket will automatically use QueryPeer for server sockets and VerifyPeer for client sockets.
         */
        case 3:
            CSSLServer::s_eSSLVerifyMode = QSslSocket::AutoVerifyPeer;
            break;
    }
}

void SocketTestQ::PrivateKeyDialog()
{
    ui->uiKeyFile->setText(QFileDialog::getOpenFileName(this, tr("Choose a private key file"), QString(), "*.*"));
}

void SocketTestQ::CertDialog()
{
    ui->uiCertFile->setText(QFileDialog::getOpenFileName(this, tr("Choose a certificate file"), QString(), "*.*"));
}

void SocketTestQ::ProcessSSLReceivedData(QByteArray SSLByteArray)
{
    if(ui->uiServerRadioHex->isChecked())
    {
        ui->uiServerLog->append(QString(SSLByteArray.toHex()));
    }
    else
    {
        ui->uiServerLog->append(QString(SSLByteArray));
    }
}

void SocketTestQ::onSSLClientDisconnected()
{
    ui->uiServerSendMsgBtn->setEnabled(false);
    ui->uiServerSendFileBtn->setEnabled(false);
    ui->uiServerBrowseBtn->setEnabled(false);
    ui->uiServerDisconnectBtn->setEnabled(false);
    ui->uiServerGroupBoxConnection->setTitle( tr("Connected Client : < NONE >") );
    ui->uiServerLog->append(tr("SSL Client closed conection."));
}

void SocketTestQ::onNewSSLClient(QSslSocket* pSocket)
{
    ui->uiServerGroupBoxConnection->setTitle( tr("Connected SSL Client : < ") + (pSocket->peerAddress()).toString() +tr(" >") );
    ui->uiServerLog->append(tr("New SSL Client addr: ") + (pSocket->peerAddress()).toString());
    ui->uiServerSendMsgBtn->setEnabled(true);
    ui->uiServerSendFileBtn->setEnabled(true);
    ui->uiServerBrowseBtn->setEnabled(true);
    ui->uiServerDisconnectBtn->setEnabled(true);
}




//clean
void SocketTestQ::on_clearButton_clicked()
{
    ui->textEdit->clear();
    ui->lineEdit->clear();
    ui->textEdit_4->clear();
    ui->textEdit_2->clear();
    ui->textEdit_3->clear();
}

//send data,to hex
/*机器人发送串口数据*/
void SocketTestQ::on_sendButton_clicked()
{
    //将协议一一发送
    QByteArray senddata;
    QString output;
    for(int i=0;i<5;i++)
    {
        output=output+ctrl[i];
    }
    serial->write(QString2Hex(output));
    qDebug() << "send byte array is:"<<output;
    //qDebug() <<"string is:" <<ui->textEdit_2->toPlainText();

 }

//read the data

int SocketTestQ::hex2Int(QChar num)
{
    if(num=='0')return 0;
    if(num=='1')return 1;
    if(num=='2')return 2;
    if(num=='3')return 3;
    if(num=='4')return 4;
    if(num=='5')return 5;
    if(num=='6')return 6;
    if(num=='7')return 7;
    if(num=='8')return 8;
    if(num=='9')return 9;
    if(num=='a')return 10;
    if(num=='b')return 11;
    if(num=='c')return 12;
    if(num=='d')return 13;
    if(num=='e')return 14;
    if(num=='f')return 15;
}

/*机器人接收串口数据*/
void SocketTestQ::Read_Data()
{
    if(mode==1)
    {
        QByteArray buf;
        buf = serial->readAll();
        //byte array
        if(!buf.isEmpty())
        {
            ui->lineEdit_2->clear();
//            //  byte0为高 8 位
//            int data1= (unsigned char)buf.at(0);  // 取出 对应位的16进制char型之后转换为16进制的int型（强制转换）
//            //  byte1为低 8 位
//            int data2= (unsigned char)buf.at(1);  // 取出 对应位的16进制char型之后转换为16进制的int型（强制转换）
//            int data_sum= data1<<8|data2;//移位8位是一个字节
//            // 将16进制data_sum转换为string类型的10进制数便于在text上显示
            QString str = ui->textEdit->toPlainText();
            QString string = buf;
            QByteArray data_hand =QString2Hex(string);
            uint16_t T;
            uint8_t high;
            uint8_t low;
            //appendArray(data_hand);
            //RecData.append(data_hand);
            QString da=buf.toHex();
            int result=0;
            for(int n=0;n<4;n++)
            {
                result=result+hex2Int(da[n])*qPow(16,(3-n));
            }
            temp=result;
            double tem=temp;
            tem=tem/10;
            QString q= QString::number(tem,10,1);
            ui->lineEdit_2->setText(q);
            str += buf.toHex();
            QString str2 = ui->textEdit_4->toPlainText();
            str2 += buf.toHex();
            ui->textEdit->clear();
            if(click_uid)
            {
                //clear first
                ui->lineEdit->clear();
                ui->lineEdit->setText(str);
                click_uid = false;
            }
            else if(click_anti)
            {
                ui->textEdit_4->clear();
                ui->textEdit_4->append(str2);
                if((ui->textEdit_4->toPlainText()).length() == 10) click_anti = false;
            }
            else if(click_sqa)
            {
                ui->textEdit_3->clear();
                ui->textEdit_3->append(str);
                click_sqa = false;
            }
            else  ui->textEdit->append(str);
        }
        buf.clear();
    }


    if(mode==2)
    {
        QByteArray temp = serial->readAll();
        if(!temp.isEmpty())
        {
            byteArray.append(temp);

            if(byteArray.contains("#-*"))
            {

                QByteArray array=byteArray.left(byteArray.indexOf("#-*"));
                QImage image;
                bool flag;
                qDebug() <<array.length();
                if(array.length()==153665)
                {
                    QByteArray array2=array.insert(0,"B");
                    flag=image.loadFromData(array2,"bmp");
                    image.save(QString("D:/Qt/test.bmp"), "bmp");
                }
                else
                {
                    flag=image.loadFromData(array,"bmp");
                    image.save(QString("D:/Qt/test.bmp"), "bmp");
                }
                qDebug() <<array[0];
                if (flag)
                {

                    qDebug() <<"here!";
                    QPixmap pixmap=QPixmap::fromImage(image);
                    ui->labelImage->setPixmap(pixmap);

                }
                byteArray.clear();
            }

        }
    }

}


//open the serial
void SocketTestQ::on_openButton_clicked()
{
    if(ui->openButton->text()==tr("Open Serial"))
    {
        serial = new QSerialPort;
        //port
        serial->setPortName(ui->PortBox->currentText());
        //serial
        serial->open(QIODevice::ReadWrite);
        //baud rate
        serial->setBaudRate(ui->BaudBox->currentText().toInt());
        //data bits
        switch(ui->BitNumBox->currentIndex())
        {
        case 8: serial->setDataBits(QSerialPort::Data8); break;
        default: break;
        }
        //parity
        switch(ui->ParityBox->currentIndex())
        {
        case 0: serial->setParity(QSerialPort::NoParity); break;
        default: break;
        }
        //stop bit
        switch(ui->StopBox->currentIndex())
        {
        case 1: serial->setStopBits(QSerialPort::OneStop); break;
        case 2: serial->setStopBits(QSerialPort::TwoStop); break;
        default: break;
        }
        //flow control
        serial->setFlowControl(QSerialPort::NoFlowControl);

        //close enable
        ui->PortBox->setEnabled(false);
        ui->BaudBox->setEnabled(false);
        ui->BitNumBox->setEnabled(false);
        ui->ParityBox->setEnabled(false);
        ui->StopBox->setEnabled(false);
        ui->openButton->setText(tr("Close Serial"));
        ui->sendButton->setEnabled(true);

        //connect
        //read_data:signal ; slot:read_data;
        //QObject::connect(serial, &QSerialPort::readyRead, this, &SocketTestQ::Read_Data);
        connect(serial,SIGNAL(readyRead()),this,SLOT(Read_Data()));
        click_uid = false;
        click_anti = false;
        click_sqa = false;
    }
    else
    {
        //close serial
        serial->clear();
        serial->close();
        serial->deleteLater();

        //enable
        ui->PortBox->setEnabled(true);
        ui->BaudBox->setEnabled(true);
        ui->BitNumBox->setEnabled(true);
        ui->ParityBox->setEnabled(true);
        ui->StopBox->setEnabled(true);
        ui->openButton->setText(tr("Open Serial"));
        ui->sendButton->setEnabled( false);
    }

}
//find the card
void SocketTestQ::on_pushButton_clicked()
{
    click_uid = true;
    QByteArray array_sel_uid{sel_uid,sizeof(sel_uid)};
    qDebug() << array_sel_uid;
    if(ui->openButton->text()==tr("Close Serial"))
    {
  //      QString str_input = "&?;";
        serial->write(array_sel_uid);
    }
    else
    {
      QMessageBox::information(this,"warning","please open the serial");
    }
}

//select card anti 9320
void SocketTestQ::on_pushButton_2_clicked()
{
    click_anti = true;
    QByteArray array_sel_anti{sel_anti,sizeof(sel_anti)};
    if(ui->openButton->text()==tr("Close Serial"))
    {
 //       QString str_input = "T]?;";
        serial->write(array_sel_anti);
    }
    else
    {
        QMessageBox::information(this,"warning","please open the serial");
    }
}

//SQA
void SocketTestQ::on_pushButton_3_clicked()
{
    click_sqa = true;
    QByteArray array_sel_sqa{sel_sqa,sizeof(sel_sqa)};
    if(ui->openButton->text()==tr("Close Serial"))
    {
        serial->write(array_sel_sqa);
    }
    else
    {
        QMessageBox::information(this,"warning","please open the serial");
    }
}
//hexstr -> str(10)
QByteArray SocketTestQ::getByteArray(QString str)
{
    QByteArray packet;
    bool bNonHexSymbol = false;
//    QString strTmp = ui->uiUdpMsg->text().toUpper();
    QString strTmp = str;
    for(int c = 0; c < strTmp.toUtf8().length(); c++)
    {
        if (strTmp.toUtf8().at(c) >= '0' && strTmp.toUtf8().at(c) <= '9')
        {
            packet.append( (strTmp.toUtf8().at(c) - 48) );
            qDebug() << (strTmp.toUtf8().at(c) - 48);
        }
        else if(strTmp.toUtf8().at(c) >= 'A' && strTmp.toUtf8().at(c) <= 'F' )
        {
            packet.append( (strTmp.toUtf8().at(c) - 55) );
            qDebug() << (strTmp.toUtf8().at(c) - 55);
        }
        else
            bNonHexSymbol = true;
      }
    return packet;
}
//ASCLL -> hexstr
QString SocketTestQ::byteArrayToHexString(QString str)
{
    QString temp ="";
    QString single = "";
    bool ok;
    /*
    for(int i = 0;i < str.length();i++)
    {
        single = str[i] - '0' + 48;
        qDebug() << "single is " << single.toInt(&ok,16);
        temp += QString::number(single.toInt(&ok,16),16);
    }*/
    temp = str.toInt(&ok,16);
    qDebug() << temp;
    return temp;
}
//hexstr -> ascllstr
QString SocketTestQ::hexToAscall(QString in)
{
    std::string c_str = in.toStdString();
    std::string result = "";
    std::string temp3 = "";
    int first;
    int second;
    for(int i = 0; i < c_str.length(); i += 2)
    {
        if(c_str[i] - '0' > 10) first = 10 + c_str[i] - 'a';
        else first = c_str[i] - '0';
        if(c_str[i + 1] - '0' > 10) second = 10 + c_str[i + 1] - 'a';
        else second = c_str[i + 1] - '0';
            temp3 = first * 16 + second * 1;
        result += temp3;
    }
    qDebug()<<"result is:" <<  QString::fromStdString(result);
    return QString::fromStdString(result);
}
QByteArray SocketTestQ::hexStringToByte(QString hex)
{
   // QByteArray result;
    int len = (hex.length() / 2);
    int first,second;
    QByteArray result;
    result.resize(len);
    //std::char[] achar = hex.toCharArray();
    std::string temp = hex.toStdString();
    for (int i = 0; i < len; i++) {
        int pos = i * 2;
        if(temp[pos] - 'a' >= 0) first = 10 + temp[pos] - 'a';
        else if(temp[pos] - 'a' >= 0) first = 10 + temp[pos] - 'A';
        else first = temp[pos] - '0';
        if(temp[pos + 1] - 'a' >= 0) second = 10 + temp[pos + 1] - 'a';
        else if(temp[pos + 1] - 'a' >= 0) second = 10 + temp[pos + 1] - 'A';
        else second = temp[pos + 1] - '0';
        result[i] = (byte) ((first) << 4 | byte(second));
    }
    return result;
}


/*机器人数据可视化*/
void SocketTestQ::test_plot(QCustomPlot *customPlot)
{


      // set dark background gradient: 设置暗背景渐变
      QLinearGradient gradient(0, 0, 0, 400);
      gradient.setColorAt(0, QColor(255, 255, 255));//开始颜色为黑色
      gradient.setColorAt(0.38, QColor(255, 255, 255));//红色
      gradient.setColorAt(1, QColor(255, 255, 255));//黑色
      customPlot->setBackground(QBrush(gradient));//设置图表背景（用画刷设置）

      // create empty bar chart objects: 这个就是创建柱状图了
      //新版本应该是取消了之前的AddPlottable
      //然后直接在new QCPBars的时候指定x，y轴就可以了
      QCPBars *fossil = new QCPBars(customPlot->xAxis, customPlot->yAxis);
      fossil->setAntialiased(false);
      fossil->setStackingGap(1);
      // set names and colors: 设置名字和颜色
      fossil->setName("Average Temperature Of Each Day");
      fossil->setPen(QPen(QColor(111, 9, 176).lighter(170)));// >100 则返回较浅的颜色
      fossil->setBrush(QColor(111, 9, 176));
      // prepare x axis with country labels: //设置x轴标签
      QVector<double> ticks;
      QVector<QString> labels;
      ticks << 1 << 2 << 3 << 4 << 5 << 6 << 7;
      labels << "5.15" << "5.16" << "5.17" << "5.18" << "5.19" << "5.20" << "5.21";
      QSharedPointer<QCPAxisTickerText> textTicker(new QCPAxisTickerText);
      textTicker->addTicks(ticks, labels);
      customPlot->xAxis->setTicker(textTicker);
      customPlot->xAxis->setTickLabelRotation(60);//设置标签角度旋转
      customPlot->xAxis->setSubTicks(false);//设置是否显示子标签
      customPlot->xAxis->setTickLength(0, 4);
      customPlot->xAxis->setRange(0, 8);//设置x轴区间
      customPlot->xAxis->setBasePen(QPen(Qt::black));
      customPlot->xAxis->setTickPen(QPen(Qt::black));
      customPlot->xAxis->grid()->setVisible(true);//设置网格是否显示
      customPlot->xAxis->grid()->setPen(QPen(QColor(130, 130, 130), 0, Qt::DotLine));
      customPlot->xAxis->setTickLabelColor(Qt::black);//设置标记标签颜色
      customPlot->xAxis->setLabelColor(Qt::black);

      // prepare y axis: //设置y轴
      customPlot->yAxis->setRange(0, 12.1);
      customPlot->yAxis->setPadding(5); // a bit more space to the left border 设置左边留空间
      customPlot->yAxis->setLabel("Temperature /℃");
      customPlot->yAxis->setBasePen(QPen(Qt::black));
      customPlot->yAxis->setTickPen(QPen(Qt::black));
      customPlot->yAxis->setSubTickPen(QPen(Qt::black));//设置SubTick颜色，SubTick指的是轴上的
                                                        //刻度线
      customPlot->yAxis->grid()->setSubGridVisible(true);
      customPlot->yAxis->setTickLabelColor(Qt::black);//设置标记标签颜色（y轴标记标签）
      customPlot->yAxis->setLabelColor(Qt::black);//设置标签颜色（y轴右边标签）
      customPlot->yAxis->grid()->setPen(QPen(QColor(130, 130, 130), 0, Qt::SolidLine));
      customPlot->yAxis->grid()->setSubGridPen(QPen(QColor(130, 130, 130), 0, Qt::DotLine));

      // Add data:添加数据
      QVector<double> fossilData, nuclearData, regenData;
      fossilData  << 20 << 16 << 25 << 18 << 26 << 23 << 15;//数据读取部分需要重写，暂时用这些代替
      //setData(QVector<double> , QVector<double>) 第一个参数是指定哪条bar
      fossil->setData(ticks, fossilData);

      // setup legend: 设置标签
      customPlot->legend->setVisible(true);
      customPlot->axisRect()->insetLayout()->setInsetAlignment(0, Qt::AlignTop|Qt::AlignHCenter);
      customPlot->legend->setBrush(QColor(0, 0, 0, 0));
      customPlot->legend->setBorderPen(Qt::NoPen);
      QFont legendFont = font();
      legendFont.setPointSize(10);
      customPlot->legend->setFont(legendFont);
      customPlot->setInteractions(QCP::iRangeDrag | QCP::iRangeZoom);//设置 可拖动，可放大缩小
}

//void SocketTestQ::on_pushButton_4_clicked()
//{

//}


void SocketTestQ::on_DATAREAD_clicked()
{
    test_plot(ui->customPlot);
    QByteArray senddata;
    for(int i=0;i<ctrl->length();i++)
    {

        qDebug() <<ctrl[i];
    }
}

void SocketTestQ::timerEvent(QTimerEvent *event)
{
    Q_UNUSED(event);

    if(event->timerId() == refreshTimer)//30ms
    {
        double xHigh = getNow() - 0.5;
        ui->plot->xAxis->setRange(xHigh - ui->plot->xAxis->range().size(), xHigh);
        ui->plot->replot();
    }


    if(event->timerId() == sampleTimer)//500ms
    {
        ui->sendButton->click();
        newPoint.setX(getNow());
        double x=temp;
        x=x/10;


        jsonObject.insert("Temperature", x);
        jsonObject.insert("PH", 0);
        jsonObject.insert("Attitude", "stable");
        jsonObject.insert("Error", 0);
        jsonObject.insert("Time", QDateTime::currentDateTime().toString());
        jsonSave.insert(QString::number(num),jsonObject);
        num++;

        // 使用QJsonDocument设置该json对象


        newPoint.setY(x);//模拟收到新的采样点qSin(100 * lastPoint.x())
        //qDebug() <<x;
        cnt = 0;
        //qDebug() << newPoint.x() <<  newPoint.y();

        /*在新的点和上一个采样点之间，线性插值100个点，但并不立即显示*/
        /*这里以线性插值为例。其余类型的插值只需替换这一部分即可*/
        int n = 100;
        double dx = (newPoint.x() - lastPoint.x()) / 100.0;//线性插值
        double dy = (newPoint.y() - lastPoint.y()) / 100.0;//线性插值
        for(int i = 1; i <= n; i++)
        {
            ui->plot->graph(0)->addData(lastPoint.x() + dx * i, lastPoint.y() + dy * i);
        }
        lastPoint.setX(newPoint.x());
        lastPoint.setY(newPoint.y());
    }
}
double SocketTestQ::getNow()
{
    return (double)(QDateTime::currentMSecsSinceEpoch()) / 1000.0;
}

int SocketTestQ::bytesToInt(QByteArray bytes)
{
    int addr = bytes[0] & 0x000000FF;
    addr |= ((bytes[1] << 8) & 0x0000FF00);
    addr |= ((bytes[2] << 16) & 0x00FF0000);
    addr |= ((bytes[3] << 24) & 0xFF000000);
    return addr;
}

/*机器人运动控制*/
void SocketTestQ::on_pushButton_5_clicked()//上
{
    QDateTime time;
    QString strBuffer;
    time = QDateTime::currentDateTime();
    strBuffer = time.toString("hh:mm:ss");
    ctrl[1]="A1";
    ui->textEdit_2->append(strBuffer+"\tRobot up");
    ui->textEdit_2->append("DATA:"+ctrl[0]+ctrl[1]+ctrl[2]+ctrl[3]+ctrl[4]);
    qDebug()<<ctrl[0];
}

void SocketTestQ::on_FORWARD_BTN_clicked()//前进
{
    QDateTime time;
    QString strBuffer;
    time = QDateTime::currentDateTime();
    strBuffer = time.toString("hh:mm:ss");
    ctrl[1]="A3";
    ui->textEdit_2->append(strBuffer+"\tRobot moves forward");
    ui->textEdit_2->append("DATA:"+ctrl[0]+ctrl[1]+ctrl[2]+ctrl[3]+ctrl[4]);
}

void SocketTestQ::on_BACK_BTN_clicked()//后退
{
    QDateTime time;
    QString strBuffer;
    time = QDateTime::currentDateTime();
    strBuffer = time.toString("hh:mm:ss");
    ctrl[1]="A4";
    ui->textEdit_2->append(strBuffer+"\tRobot moves back");
    ui->textEdit_2->append("DATA:"+ctrl[0]+ctrl[1]+ctrl[2]+ctrl[3]+ctrl[4]);
}

void SocketTestQ::on_pushButton_6_clicked()//下
{
    QDateTime time;
    QString strBuffer;
    time = QDateTime::currentDateTime();
    strBuffer = time.toString("hh:mm:ss");
    ctrl[1]="A2";
    ui->textEdit_2->append(strBuffer+"\tRobot down");
    ui->textEdit_2->append("DATA:"+ctrl[0]+ctrl[1]+ctrl[2]+ctrl[3]+ctrl[4]);
}

void SocketTestQ::on_pushButton_7_clicked()//左
{
    QDateTime time;
    QString strBuffer;
    time = QDateTime::currentDateTime();
    strBuffer = time.toString("hh:mm:ss");
    ctrl[1]="A5";
    ui->textEdit_2->append(strBuffer+"\tRobot moves left");
    ui->textEdit_2->append("DATA:"+ctrl[0]+ctrl[1]+ctrl[2]+ctrl[3]+ctrl[4]);
}

void SocketTestQ::on_pushButton_8_clicked()//右
{
    QDateTime time;
    QString strBuffer;
    time = QDateTime::currentDateTime();
    strBuffer = time.toString("hh:mm:ss");
    ctrl[1]="A6";
    ui->textEdit_2->append(strBuffer+"\tRobot moves right");
    ui->textEdit_2->append("DATA:"+ctrl[0]+ctrl[1]+ctrl[2]+ctrl[3]+ctrl[4]);
}

void SocketTestQ::on_StopButton_clicked()
{
    QDateTime time;
    QString strBuffer;
    time = QDateTime::currentDateTime();
    strBuffer = time.toString("hh:mm:ss");
    ctrl[1]="A7";
    ctrl[3]="00";
    ui->textEdit_2->append(strBuffer+"\tRobot stops");
    ui->textEdit_2->append("DATA:"+ctrl[0]+ctrl[1]+ctrl[2]+ctrl[3]+ctrl[4]);
}


void SocketTestQ::slotReadData()
{
    QByteArray temp = serial->readAll();
//    QByteArray data = serial->readAll();
//    QByteArray buffer;
//    foreach(char b,data)
//    {
//            if(b != '\n')
//            {
//                buffer.append(b);
//            }
//            else
//            {
//                QImage image;
//                            //bool flag=image.loadFromData((const uchar *)array.data(),array.size());
//                            bool flag=image.loadFromData(buffer,"bmp");
//                            qDebug() <<buffer.length();
//                            image.save(QString("D:/Qt/test.bmp"), "bmp");
//                            if (flag)
//                            {

//                                qDebug() <<"here!";
//                                QPixmap pixmap=QPixmap::fromImage(image);
//                                ui->labelImage->setPixmap(pixmap);

//                            }
//                buffer.clear();
//            }
//     }
    if(!temp.isEmpty())
    {
        byteArray.append(temp);

        if(byteArray.contains("#-*"))
        {

            QByteArray array=byteArray.left(byteArray.indexOf("#-*"));
            //ui->textEdit_5->append(array);
            QImage image;
            bool flag;
            //bool flag=image.loadFromData((const uchar *)array.data(),array.size());

            qDebug() <<array.length();
            if(array.length()==153665)
            {
                QByteArray array2=array.insert(0,"B");
                flag=image.loadFromData(array2,"bmp");
                image.save(QString("D:/Qt/robot/test.bmp"), "bmp");
            }
            else
            {
                flag=image.loadFromData(array,"bmp");
                image.save(QString("D:/Qt/robot/test.bmp"), "bmp");
            }
            qDebug() <<array[0];
            if (flag)
            {

                qDebug() <<"here!";
                QPixmap pixmap=QPixmap::fromImage(image);
                ui->labelImage->setPixmap(pixmap);

            }
            byteArray.clear();
            //byteArray = byteArray.right(byteArray.length()-byteArray.indexOf("###")-3);
        }

    }
}

void SocketTestQ::on_camButton_clicked()
{
    mode=2;
}

void SocketTestQ::on_dataButton_clicked()
{
    mode=1;
}

void SocketTestQ::on_lowSpeedButton_clicked()
{

    ctrl[3]="2C";
}

void SocketTestQ::on_highSpeedButton_clicked()
{
    ctrl[3]="4C";
}

/*机器人数据存储*/
void SocketTestQ::on_SaveButton_clicked()
{
    QFile file("D:/Qt/robot/data.json");
    if(!file.open(QIODevice::ReadWrite))
    {
        qDebug() << "File open error";
    }else
    {
        qDebug() <<"File open!";
    }
    jsonArray.append(jsonSave);
    QJsonDocument jsonDoc;
    jsonDoc.setObject(jsonObject);
    // 将json以文本形式写入文件并关闭文件。
    jsonDoc.setArray(jsonArray);
    file.write(jsonDoc.toJson());
    file.close();
}




