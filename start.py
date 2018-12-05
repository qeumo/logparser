from tkinter import *
from tkinter import filedialog, messagebox
import re
import csv
import parserIP # File with IPs
import userag   # File with Useragents
from collections import Counter
import os
# Ниже паттерн строки лога, нужен для разбиения на группы и поиска нужных значений
LOG_PATTERN = r'^(\S+) (\S+) (\S+) \[([\w:/]+\s[+\-]\d{4})\] "(\S+)\s?(\S+)?\s?(\S+)?" (\d{3}|-) (\d+|-)\s?"?([^"]*)"?\s?"?([^"]*)?"?$'
logs = ''

def canvasFrameCa(event): # Функция для функционирования колеса прокрутки фрейма FrameCa (IP)
    canvas.configure(scrollregion=canvas.bbox("all"),width=300,height=250)
def canvasFrameCa2(event): # Функция для функционирования колеса прокрутки фрейма FrameCa2 (USERAGENT)
    canvas1.configure(scrollregion=canvas1.bbox("all"),width=1000,height=150)
def canvasFrameCa3(event): # Функция для функционирования колеса прокрутки фрейма FrameCa3 (LOG)
    canvas2.configure(scrollregion=canvas2.bbox("all"),width=465,height=330)

def checkBTN(): # Проверка IP с коэфом
    try:
        if entry2.get()!='':
            summ=0
            total=0
            param = int(entry2.get())
            parserIP.write_csv(parserIP.count(parserIP.reader(logs)),param)
            with open('outputGood.csv', newline='') as csvfile:
                ipp = csv.reader(csvfile, delimiter=',')
                k=0
                for row in ipp:
                    if row != []:
                        if row[1]!='Frequency':
                            summ+=int(row[1])
                            total+=1
                #print(total)
            with open('outputSuspicious.csv', 'w') as csvfile: 
                writer = csv.writer(csvfile)
                header = ['Suspicious IP', 'Frequency']
                writer.writerow(header)
                suspIndicator = (summ/total)*param/10
                regexp = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
                count = Counter(re.findall(regexp, logs))
                for item in count:
                    if count[item] > suspIndicator:
                        writer.writerow((item,count[item]))
            with open('outputSuspicious.csv', newline='') as csvfile:
                ip = csv.reader(csvfile, delimiter=',')
                i=0
                for row in range(total+1):
                    label1 = Label(Frame1_1, text = '                          ').grid(row=i,column=2)
                    label1 = Label(Frame1_1, text = '                          ').grid(row=i,column=3)
                    i+=1
                i=0
                for row in ip:
                    
                    if row != []:
                        label1 = Label(Frame1_1, text = row[0]).grid(row=i,column=2)
                        label2 = Label(Frame1_1, text = row[1]).grid(row=i,column=3)
                        
                        i+=1
                        print(row)
    except:
        messagebox.showerror("Ошибка!", "Введите правильный параметр или снова загрузите файл лога")
    if entry1.get()!='':
        sus = 0
        good = 0
        with open('outputGood.csv', newline='') as csvfile:
            ippp = csv.reader(csvfile, delimiter=',')
            k=0
            for row in ippp:
                if row != []:
                    if row[0]==entry1.get():
                        print('est v goods')
                        good = 1
                        zapros = row[1]
                        with open('outputSuspicious.csv', newline='') as csvfile:
                            izp = csv.reader(csvfile, delimiter=',')
                            i=0
                            for row in izp:
                                if row != []:
                                    if row[0]==entry1.get():
                                        print('est v susp')
                                        sus = 1
                                        zapros = row[1]
        t = '                      '
        Label(Frame1,text=t+'\n'+t+'\n'+t+'\n'+t,font='Arial 200', bg='lightgray').place(x=385,y=250)
        if good == 0:
            print('NOT FOUND')
            label = Label(Frame1, text='IP ' + entry1.get() + ' \nне найден!',font='Arial 14',fg='black', bg='lightgray')
        if good == 1 and sus == 0:
            print('good')
            label = Label(Frame1,text='IP ' + entry1.get() + ' \nхороший!\nКол-во запросов:\n' + zapros, font='Arial 14',fg='green', bg='lightgray')
        if sus == 1:
            print('susp')
            label = Label(Frame1,text='IP ' + entry1.get() + ' \nподозрительный!\nКол-во запросов:\n' + zapros, font='Arial 14',fg='red', bg='lightgray')
        
        label.place(x=385,y=250) # Кнопка проверки IP на подозрительность

def IPanz(): # Заполнение окна ипов
    if entry2.get()!='':
        param = int(entry2.get())
        parserIP.write_csv(parserIP.count(parserIP.reader(logs)),param)
    try:
        with open('outputGood.csv', newline='') as csvfile:
            ip = csv.reader(csvfile, delimiter=',')
            
            i=0
            for row in ip:
                if row != []:
                    label1 = Label(Frame1_1, text = row[0]).grid(row=i,column=0)
                    label2 = Label(Frame1_1, text = row[1]).grid(row=i,column=1)
                    
                    i+=1
                    print(row)

        with open('outputSuspicious.csv', newline='') as csvfile:
            ip = csv.reader(csvfile, delimiter=',')
            
            i=0
            for row in ip:
                
                if row != []:
                    label1 = Label(Frame1_1, text = row[0]).grid(row=i,column=2)
                    label2 = Label(Frame1_1, text = row[1]).grid(row=i,column=3)
                    
                    i+=1
                    print(row)
    except:
        messagebox.showerror("Ошибка!", "Лог не найден! \nЗагрузите лог через кнопку Загрузить")# Заполнение окна со списком IP и частотами  #

def userAg(): # Заполнение списка юзерагентов

    with open('userAgent.csv', newline='') as csvfile:
            ua = csv.reader(csvfile, delimiter=',')
            
            i=0
            for row in ua:
                if row != []:
                    label1 = Label(Frame3_1, text = row[0]).grid(row=i,column=0)
                    label2 = Label(Frame3_1, text = row[1]).grid(row=i,column=1)
                    
                    i+=1

def logList():# Заполнение фрейма с логом
    i=1
    with open('logs.log', newline='') as f:
        loge = f.readlines()
    for line in loge:
        match = re.search(LOG_PATTERN, line)
        # Группы
        host          = match.group(1)
        date_time     = match.group(4)
        method        = match.group(5)
        protocol      = match.group(7)
        response_code = int(match.group(8))
        content_size  = match.group(9)

        Label(Frame2_1, text = 'IP').grid(row=0,column=0)
        Label(Frame2_1, text = 'Дата и время').grid(row=0,column=1)
        Label(Frame2_1, text = 'Метод').grid(row=0,column=2)
        Label(Frame2_1, text = 'Протокол').grid(row=0,column=3)
        Label(Frame2_1, text = 'Код').grid(row=0,column=4)
        Label(Frame2_1, text = 'Размер пакетов').grid(row=0,column=5)

        Label(Frame2_1, text = host).grid(row=i,column=0)
        Label(Frame2_1, text = date_time).grid(row=i,column=1)
        Label(Frame2_1, text = method).grid(row=i,column=2)
        Label(Frame2_1, text = protocol).grid(row=i,column=3)
        Label(Frame2_1, text = response_code).grid(row=i,column=4)
        Label(Frame2_1, text = content_size).grid(row=i,column=5)

        i+=1

def Quit(): # Exit and deleting all created files
    try:
        os.remove("temp.txt")
    except:
        print('No temp.txt')
    try:
        os.remove("outputGood.csv")
    except:
        print('No outputGood.csv')
    try:
        os.remove("outputSuspicious.csv")
    except:
        print('No outputSuspicious.csv')
    try:
        os.remove("userAgent.csv")
    except:
        print('No userAgent.csv')
    exit()

def LoadFile(): # File load button
    global logs
    fn = filedialog.Open(root, filetypes = [('*.log files', '.log')]).show()
    if fn == '':
        return
    logs = open(fn, 'rt').read()
    parserIP.write_csv(parserIP.count(parserIP.reader(logs)))
    userag.write_csv(userag.count(userag.reader(logs)))
    logList()
    userAg()

root = Tk()
root.title('Анализ логов веб сервера')
root.geometry("1170x620")
#-------------------------------------
# Ниже фрейм со списком уникальных юзерагентов и их кол-ва
#-------------------------------------
Frame3 = Frame(root, height = 200, width = 1050 ,borderwidth=5)
Frame3.place(x=20,y=400)

FrameCa2 = Frame(Frame3, height = 100, width = 1000,relief=GROOVE, bd=1)
FrameCa2.place(x=0,y=25)
canvas1=Canvas(FrameCa2 )
Frame3_1=Frame(canvas1 , height = 25, width = 1000)

myscrollbar=Scrollbar(FrameCa2,orient="vertical",command=canvas1.yview)
canvas1.configure(yscrollcommand=myscrollbar.set)

myscrollbar.pack(side="right",fill="y")
canvas1.pack(side="left")
canvas1.create_window((0,0),window=Frame3_1,anchor='nw')
Frame3_1.bind("<Configure>",canvasFrameCa2)


#-------------------------------------
# Ниже фрейм с логом
#-------------------------------------
Frame2 = Frame(root, height = 350, width = 500, bg='lightgray', bd=5)
Frame2.place(x=650,y=20)

FrameCa3 = Frame(Frame2, height = 100, width = 1000,relief=GROOVE, bd=1)
FrameCa3.place(x=0,y=0)
canvas2=Canvas(FrameCa3 )
Frame2_1=Frame(canvas2 , height = 250, width = 1000)

myscrollbar=Scrollbar(FrameCa3,orient="vertical",command=canvas2.yview)
canvas2.configure(yscrollcommand=myscrollbar.set)

myscrollbar.pack(side="right",fill="y")
canvas2.pack(side="left")
canvas2.create_window((0,0),window=Frame2_1,anchor='nw')
Frame2_1.bind("<Configure>",canvasFrameCa3)
#-------------------------------------
# Ниже фрейм с анализом IP
#-------------------------------------
Frame1 = Frame(root, height = 350, width = 600,bg='lightgray', borderwidth=5)
Frame1.place(x=20,y=20)

FrameCa = Frame(Frame1, height = 250, width = 300,relief=GROOVE, bd=1)
FrameCa.place(x=10,y=52)
canvas=Canvas(FrameCa )
Frame1_1=Frame(canvas )

myscrollbar=Scrollbar(FrameCa,orient="vertical",command=canvas.yview)
canvas.configure(yscrollcommand=myscrollbar.set)

myscrollbar.pack(side="right",fill="y")
canvas.pack(side="left")
canvas.create_window((0,0),window=Frame1_1,anchor='nw')
Frame1_1.bind("<Configure>",canvasFrameCa)

Label(Frame1, font='Arial 9', text='IP', bg='lightgray').place(x=50,y=30)
Label(Frame1, font='Arial 9', text='Частота', bg='lightgray').place(x=100,y=30)
Label(Frame1, font='Arial 9', text='Подозрит IP', bg='lightgray').place(x=165,y=30)
Label(Frame1, font='Arial 9', text='Частота', bg='lightgray').place(x=255,y=30)
Label(Frame1, font='Arial 14', text='IP запросов на сервер', bg='lightgray').place(x=55,y=6)
Label(Frame1, font='Arial 14', text='Проверка IP', bg='lightgray').place(x=420,y=10)
Label(Frame1, font='Arial 10', text='Введите IP', bg='lightgray').place(x=350,y=60)
Label(Frame1, font='Arial 10', text='Введите параметр подозрительности IP', bg='lightgray').place(x=350,y=110)
Label(Frame1, font='Arial 10', bg='lightgray', text='Вычисление подозрительного IP:\nСреднее кол-во IP * Параметр/10\nСтандартный параметр = 15').place(x=360,y=180)

entry1 = Entry(Frame1)
entry1.place(x=350,y=80)
entry2 = Entry(Frame1,text='1.5')
entry2.place(x=350,y=130)
butt = Button(Frame1, text='Проверить', height = 2, width = 10, command=checkBTN)
butt.place(x=500,y=60)

#-------------------------------------
# Ниже фрейм с меню
#-------------------------------------
panelFrame = Frame(root, height = 50, width = 150, bg = 'lightgray')
panelFrame.place(x=20,y=350)
loadBtn = Button(panelFrame, text = 'Загрузить',font='Arial 15', command = LoadFile)
quitBtn = Button(panelFrame, text = 'Выйти',font='Arial 15', command = Quit)
IPanzBtn = Button(panelFrame, text = 'Обновить',font='Arial 15', command = IPanz)

loadBtn.grid(row=0,column=0,padx=10,pady=5)
quitBtn.grid(row=0,column=1,padx=10,pady=5)
IPanzBtn.grid(row=0,column=2,padx=10,pady=5)
#-------------------------------------
# Вызов функций заполнения данных
try:
    IPanz()
    userAg()
    logList()
except:
    print("error")
#-------------------------------------


root.mainloop()