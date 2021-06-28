#include <QApplication>
#include "SocketTestQ.h"

int main(int argc, char* argv[])
{
#if QT_VERSION < QT_VERSION_CHECK(5, 0, 0)
  QApplication::setGraphicsSystem("raster");
#endif
    QApplication App(argc, argv);

    SocketTestQ ProgramWindow;
    ProgramWindow.show();

    return App.exec();
}
