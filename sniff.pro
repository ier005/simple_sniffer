#-------------------------------------------------
#
# Project created by QtCreator 2016-12-02T19:58:30
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = sniff
TEMPLATE = app


SOURCES += main.cpp\
        mainwindow.cpp \
    errodialog.cpp \
    filterdialog.cpp \
    thread.cpp \
    searchdialog.cpp \
    ipdefrag.cpp \
    tcpdefrag.cpp \
    tcpdialog.cpp

HEADERS  += mainwindow.h \
    errodialog.h \
    filterdialog.h \
    thread.h \
    searchdialog.h \
    ipdefrag.h \
    tcpdefrag.h \
    tcpdialog.h

FORMS    += mainwindow.ui \
    errodialog.ui \
    filterdialog.ui \
    searchdialog.ui \
    tcpdialog.ui

LIBS += -L/usr/include -lpcap
