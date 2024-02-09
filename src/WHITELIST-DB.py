import tkinter as tk
from tkinter import filedialog, ttk

import os
import re
import zipfile
import sqlite3
from itertools import islice
from threading import Thread

#DEBUG
import datetime
def now():
    return datetime.datetime.now()
import time
def ms():
    return round(time.time() * 1000.0)
import hashlib
#ENDOF-DEBUG

#GLOBAL VARIABLES
outputDirectory = "./output/"
terminateThread = False

def unzipEverything(file_paths, specific_progressbar, progress_description, specific_progress_label):
    def getZipCount(file_list):
        zip_count = 0
        for file in file_list:
            filename, file_extension = os.path.splitext(file)
            if file_extension == '.zip':
                zip_count += 1
        return zip_count

    def getListOfAllFiles(directory):
        all_files = []
        for foldername, subfolders, filenames in os.walk(directory):
            for filename in filenames:
                file_path = os.path.join(foldername, filename)
                all_files.append(file_path)
        return all_files

    totalZipCount = getZipCount(file_paths)
    totalUnzippedCount = 0

    filesUnzipped = False
    newList = []
    NUM_CHUNKS = 200

    for file in file_paths:
        file_name, file_extension = os.path.splitext(file)

        if terminateThread:
            return

        if file_extension == '.zip':
            progress_description['text'] = f"Entpacke Archiv... ({totalUnzippedCount+1}/{totalZipCount})"

            zip_folder = os.path.join(os.path.dirname(file), os.path.basename(file_name))
            os.makedirs(zip_folder, exist_ok=True)

            with zipfile.ZipFile(file, 'r') as zip_ref:
                file_list = zip_ref.namelist()
                total_files = len(file_list)
                chunk_size = max(total_files // NUM_CHUNKS, 1)
                extracted_files = 0

                for i, file_name in enumerate(file_list):
                    if terminateThread:
                        return

                    zip_ref.extract(file_name, zip_folder)
                    extracted_files += 1

                    if (i + 1) % chunk_size == 0 or i == total_files - 1:
                        specific_progressbar['value'] = ((totalUnzippedCount + extracted_files / total_files) / totalZipCount) * 100
                        specific_progress_label['text'] = f"{int(specific_progressbar['value'])}%"

                        

            os.remove(file)
            filesUnzipped = True
            totalUnzippedCount += 1

            filesInZip = getListOfAllFiles(zip_folder)
            newList.extend(filesInZip)
            totalZipCount += getZipCount(filesInZip)  # add any new zip to the total amount for calculation
        else:
            newList.append(file)  # if the file is not a zip, keep it in the list

    file_paths = newList
    if filesUnzipped:
        return unzipEverything(file_paths, specific_progressbar, progress_description, specific_progress_label)
    else:
        return file_paths

def getHashOfFile(file, specific_progressbar, progress_description, specific_progress_label):
    progress_description['text'] = "Generiere Hashsumme der Ausgabedatei..."
    specific_progressbar['value'] = 0
    specific_progress_label['text'] = f"{int(specific_progressbar['value'])}%"
    hash_md5 = hashlib.md5()
    total_size = os.path.getsize(file)
    numberOfChunks = 200 # every pixel on the progress bar is equal to one chunk!!
    with open(file, "rb") as f:
        for chunk in iter(lambda chunk_size = int((total_size / numberOfChunks) + 1): f.read(chunk_size), b""):
            if terminateThread:
                return
            specific_progressbar['value'] += 1
            specific_progress_label['text'] = f"{int(specific_progressbar['value'])}%"

            
            hash_md5.update(chunk)
    specific_progressbar['value'] = 100
    specific_progress_label['text'] = f"{int(specific_progressbar['value'])}%"

    specific_progress_label.configure(text="100%")
    return hash_md5.hexdigest()

def loadHashesIntoMemory(allFiles, fetchMD5, fetchSHA1, listOfAllMD5Hashes, listOfAllSHA1Hashes, specific_progressbar, progress_description, specific_progress_label):
    stepPerFile = 100 / len(allFiles)
    for file in allFiles:
        filename, file_extension = os.path.splitext(file)
        filename = os.path.basename(file)

        if terminateThread:
            return
        #Check for known file extension and search for common patterns
        if file_extension in ['.txt', '.sql']:
            #print("Starting to load " + filename + " into memory...")
            progress_description['text'] = f"Untersuche {filename} auf Hashwerte..."
            num_lines = 0
            with open(file, "rb") as myFile:
                num_lines = sum(1 for _ in myFile)
                myFile.close()
            with open(file, "r", encoding="utf8") as file:
                numberOfChunks = 200 # every pixel on the progress bar is equal to one chunk!!
                chunk = int((num_lines / numberOfChunks) + 1) # unequalize

                if (num_lines < 50000):
                    chunk = num_lines + 1
                    numberOfChunks = 1

                chunkCounter = 1
                avgTimePerChunk = 0 #in ms
                allTimeAllChunks = 0 #in ms
                while True:
                    startChunk = ms()
                    if terminateThread:
                        return
                    nextChunk = list(islice(file, chunk))
                    eta = round(((avgTimePerChunk / 1000 / 60) * (200 - chunkCounter)), 2) #remaining time in minutes
                    #print(((avgTimePerChunk / chunkCounter) / 1000 / 60) * (200 - chunkCounter))
                    print(f"Analysiere Fragmente der Datei... ({chunkCounter}\u00A0/\u00A0{numberOfChunks})")
                    progress_description['text'] = f"Analysiere Fragmente der Datei... ({chunkCounter}\u00A0/\u00A0{numberOfChunks}) Restzeit:\u00A0{eta}\u00A0min\u00A0remaining"
                    specific_progressbar['value'] += stepPerFile / numberOfChunks
                    specific_progress_label['text'] = f"{int(specific_progressbar['value'])}%"

                    

                    for line in nextChunk:
                        if (fetchMD5):
                            #print("Checking for MD5 Hashes")  
                            pattern = re.compile(r"\b([0-9a-f]{32})\b", re.IGNORECASE)
                            listOfAllMD5Hashes.extend(re.findall(pattern, line))
                        if (fetchSHA1):
                            #print("Checking for SHA1 Hashes")
                            pattern = re.compile(r"\b([0-9a-f]{40})\b", re.IGNORECASE)
                            listOfAllSHA1Hashes.extend(re.findall(pattern, line))

                    if len(nextChunk) < chunk:
                        del nextChunk #remove from memory                  
                        break
                    chunkCounter += 1 #why are you ugly??
                    stopChunk = ms()
                    avgTimePerChunk = (allTimeAllChunks + (stopChunk-startChunk)) / (chunkCounter - 1)
                    allTimeAllChunks += (stopChunk-startChunk)
                    print((stopChunk - startChunk))
                    print(avgTimePerChunk)


                    del nextChunk #to be save
                    #print(f"Tim taken for chunk: {stopChunk-startChunk}ms.", )


        elif file_extension == '.db':
            if terminateThread:
                return
            print(f"Starting to load {filename} into memory...")
            connection = sqlite3.connect(file)
            cursor = connection.cursor()
            progress_description['text'] = f"Versuche DATENBANK ({filename}) auszulesen..."
            if fetchMD5:
                try:
                    cursor.execute("SELECT md5 FROM METADATA")
                    listOfAllMD5Hashes.extend(list({row[0] for row in cursor.fetchall()}))
                except Exception:
                    print("Tried to access a database on METADATA but failed!")
                try:
                    cursor.execute("SELECT md5 FROM FILE") #MINIMAL PACKAGES only have hashes in the FILE table
                    listOfAllMD5Hashes.extend(list({row[0] for row in cursor.fetchall()}))
                except Exception:
                    print("Tried to access a database on FILE but failed!")
            if fetchSHA1:
                try:
                    cursor.execute("SELECT sha1 FROM METADATA")
                    listOfAllSHA1Hashes.extend(list({row[0] for row in cursor.fetchall()}))
                except Exception:
                    print("Tried to access a database on METADATA but failed!")
                try:
                    cursor.execute("SELECT sha1 FROM FILE") #MINIMAL PACKAGES only have hashes in the FILE table
                    listOfAllSHA1Hashes.extend(list({row[0] for row in cursor.fetchall()}))
                except Exception:
                    print("Tried to access a database on FILE but failed!")
            connection.close()


def process_files(file_paths, fetchMD5, fetchSHA1, global_progressbar, specific_progressbar, global_progress_label, specific_progress_label, progress_description, addLog, printLog):

    def handleShutdown():
        global_progressbar['value'] = 100
        global_progress_label['text'] = f"{int(global_progressbar['value'])}%"
        specific_progressbar['value'] = 100
        specific_progress_label['text'] = f"{int(specific_progressbar['value'])}%"

        progress_description['text'] = "Prozess wurde abgebrochen..."
        addLog(f"{now().strftime('%H:%M:%S.%f')[:-4]}: Prozess wurde vom Nutzer abgebrochen...\n")
        
        global terminateThread
        terminateThread = False

        printLog()

    def getUserInput():
        user_input = "NSRL_Version_gesamt + Whitelist LKA71 Berlin (Version) + BKA KI 26 Version"
        def get_string(event=None):
            nonlocal user_input
            user_input = entry.get()
            prompt.destroy()

        prompt = tk.Toplevel()
        prompt.title("Dateinamen Eingabe")
        prompt.geometry("550x100")

        entry_label = tk.Label(prompt, text="Setzte einen Dateinamen:", font=("Helvetica", 11, "bold"), pady=10)
        entry_label.pack()

        entry = tk.Entry(prompt, width=70, font=("Helvetica", 10))
        entry.pack()
        entry.insert(0, "NSRL_Version_gesamt + Whitelist LKA71 Berlin (Version) + BKA KI 26 Version")

        entry.bind("<Return>", get_string)

        submit_button = tk.Button(prompt, text="OK", command=get_string, font=("Helvetica", 11, "bold"), width=6, height=1)
        submit_button.pack()

        prompt.wait_window()
        return user_input or "NSRL_Version_gesamt + Whitelist LKA71 Berlin (Version) + BKA KI 26 Version"

    baseFileName = getUserInput()

    if terminateThread:
        handleShutdown()
        return

    startAll = ms()
    totalAmountOfHashes = 0

    #Register the HashLists
    listOfAllMD5Hashes = []
    listOfAllSHA1Hashes = []

    #TODO: CHECK IF AT LEAST ONE HASH WAS TICKED

    #Unzip every zip
    addLog(f"{now().strftime('%H:%M:%S.%f')[:-4]}: Starte alle Archive zu entpacken...\n")
    startUnzip = ms()
    file_paths = unzipEverything(file_paths, specific_progressbar, progress_description, specific_progress_label)
    stopUnzip = ms()
    global_progressbar['value'] = 20 #1/5 done
    global_progress_label['text'] = f"{int(global_progressbar['value'])}%"
    addLog(f"{now().strftime('%H:%M:%S.%f')[:-4]}: Das entpacken aller Archive wurde beendet! ({stopUnzip-startUnzip}ms)\n")

    print(f"Finished unzipping all zips recursively. ({stopUnzip-startUnzip}ms)\n")

    if terminateThread:
        handleShutdown()
        return
    #The unzip everything function removed the file_path refferences from the .zip files and added newly found files

    #load all wanted hashes into memory 

    if (file_paths == []):
        print("NO FILES FOUND")
        return

    specific_progressbar['value'] = 0 # reset
    specific_progress_label['text'] = f"{int(specific_progressbar['value'])}%"
    addLog(f"{now().strftime('%H:%M:%S.%f')[:-4]}: Dateien werden auf Hashwerte durchsucht...\n")
    startMemLoad = ms()
    loadHashesIntoMemory(file_paths, fetchMD5, fetchSHA1, listOfAllMD5Hashes, listOfAllSHA1Hashes, specific_progressbar, progress_description, specific_progress_label)
    stopMemLoad = ms()
    specific_progressbar['value'] = 100
    specific_progress_label['text'] = f"{int(specific_progressbar['value'])}%"
    global_progressbar['value'] = 40 # 2/5 done
    global_progress_label['text'] = f"{int(global_progressbar['value'])}%"
    addLog(f"{now().strftime('%H:%M:%S.%f')[:-4]}: Es wurden alle Hashwerte extrahiert. ({stopMemLoad-startMemLoad}ms)\n")

    if terminateThread:
        handleShutdown()
        return

    addLog(f"{now().strftime('%H:%M:%S.%f')[:-4]}: Es werden alle Hashwerte auf Duplikate überprüft...\n")
    progress_description['text'] = f"Es werden alle Hashwerte (MD5:{len(listOfAllMD5Hashes)}, SHA-1:{len(listOfAllSHA1Hashes)}) auf Duplikate überprüft..."
    specific_progressbar['value'] = 10 # reset
    specific_progress_label['text'] = f"{int(specific_progressbar['value'])}%"
    startFilter = ms()
    originalMD5Size = len(listOfAllMD5Hashes)
    originalSHA1Size = len(listOfAllSHA1Hashes)
    totalAmountOfHashes = len(listOfAllMD5Hashes) + len(listOfAllSHA1Hashes)

    listOfAllMD5Hashes = [hash.upper() for hash in listOfAllMD5Hashes]
    listOfAllSHA1Hashes = [hash.upper() for hash in listOfAllSHA1Hashes]

    listOfAllMD5Hashes = set(listOfAllMD5Hashes)
    listOfAllSHA1Hashes = set(listOfAllSHA1Hashes)

    numberOfMD5Duplicates = originalMD5Size - len(listOfAllMD5Hashes)
    numberOfSHA1Duplicates = originalSHA1Size - len(listOfAllSHA1Hashes)
    totalDuplicates = numberOfMD5Duplicates + numberOfSHA1Duplicates
    stopFilter = ms()    

    specific_progressbar['value'] = 100
    specific_progress_label['text'] = f"{int(specific_progressbar['value'])}%"
    global_progressbar['value'] = 60 # 3/5 done
    global_progress_label['text'] = f"{int(global_progressbar['value'])}%"
    addLog(f"{now().strftime('%H:%M:%S.%f')[:-4]}: Alle Hashwerte wurden auf Duplikate überprüft! ({stopFilter-startFilter}ms)\n")

    if terminateThread:
        handleShutdown()
        return

    progress_description['text'] = f"Sotiere alle MD5 ({len(listOfAllMD5Hashes)}) und SHA1 ({len(listOfAllSHA1Hashes)}) Hashwerte..."
    addLog(f"{now().strftime('%H:%M:%S.%f')[:-4]}: Es werden alle Hashwerte sortiert...\n")
    specific_progressbar['value'] = 10 # reset
    specific_progress_label['text'] = f"{int(specific_progressbar['value'])}%"
    startSorted = ms()
    listOfAllMD5Hashes = sorted(listOfAllMD5Hashes)
    listOfAllSHA1Hashes = sorted(listOfAllSHA1Hashes)
    stopSorted = ms()
    specific_progressbar['value'] = 100
    specific_progress_label['text'] = f"{int(specific_progressbar['value'])}%"
    global_progressbar['value'] = 80 # 4/5 done 
    global_progress_label['text'] = f"{int(global_progressbar['value'])}%"
    addLog(f"{now().strftime('%H:%M:%S.%f')[:-4]}: Alle Hashwerte wurden sortiert! ({stopSorted-startSorted}ms)\n"   )

    if terminateThread:
        handleShutdown()
        return

    #Save all hashes into a textfile

    startOutput = ms()

    outputMD5FileName = f"{baseFileName}.MD5.txt"
    outputSHA1FileName = f"{baseFileName}.SHA1.txt"
    specific_progressbar['value'] = 0 # reset
    specific_progress_label['text'] = f"{int(specific_progressbar['value'])}%"

    if not os.path.exists(outputDirectory):
        os.makedirs(outputDirectory)

    outputMD5FilePath = os.path.join(outputDirectory, outputMD5FileName)
    outputSHA1FilePath = os.path.join(outputDirectory, outputSHA1FileName)

    outputMD5File = open(outputMD5FilePath  , "w")
    outputSHA1File = open(outputSHA1FilePath  , "w")

    if fetchMD5:
        progress_description['text'] = "Ausgabedatei wird generiert... (MD5)"
        outputMD5File.write("MD5\n") #header
        chunkSize = int(len(listOfAllMD5Hashes) / 200)
        specific_progressbar['value'] = 0 # reset 
        specific_progress_label['text'] = f"{int(specific_progressbar['value'])}%"

        if chunkSize != 0:   
            for i in range(0, len(listOfAllMD5Hashes), chunkSize):
                if terminateThread:
                    break
                specific_progressbar['value'] += 1
                specific_progress_label['text'] = f"{int(specific_progressbar['value'])}%"

                chunk = listOfAllMD5Hashes[i:i + chunkSize]          
                outputMD5File.write('\n'.join(chunk) + '\n')
        specific_progressbar['value'] = 100
        specific_progress_label['text'] = f"{int(specific_progressbar['value'])}%"


    if fetchSHA1:
        progress_description['text'] = "Ausgabedatei wird generiert... (SHA-1)"
        outputSHA1File.write("SHA-1\n") #header
        chunkSize = int(len(listOfAllSHA1Hashes) / 200)
        specific_progressbar['value'] = 0
        specific_progress_label['text'] = f"{int(specific_progressbar['value'])}%"

        if chunkSize != 0:
            for i in range(0, len(listOfAllSHA1Hashes), chunkSize):
                if terminateThread:
                    break
                specific_progressbar['value'] += 1
                specific_progress_label['text'] = f"{int(specific_progressbar['value'])}%"

                chunk =listOfAllSHA1Hashes[i:i + chunkSize]          
                outputSHA1File.write('\n'.join(chunk))
        specific_progressbar['value'] = 100
        specific_progress_label['text'] = f"{int(specific_progressbar['value'])}%"


    if terminateThread:
        handleShutdown()
        return

    stopOutput = ms()
    specific_progressbar['value'] = 100
    specific_progress_label['text'] = f"{int(specific_progressbar['value'])}%"
    global_progressbar['value'] = 100 # 5/5 don
    global_progress_label['text'] = f"{int(global_progressbar['value'])}%"
    addLog(f"{now().strftime('%H:%M:%S.%f')[:-4]}: Ausgabedatei wurde generiert! ({stopOutput-startOutput}ms)\n")

    #Hash the output

    MD5OutputHash = getHashOfFile(outputMD5FilePath, specific_progressbar, progress_description, specific_progress_label)
    SHA1OutputHash = getHashOfFile(outputSHA1FilePath, specific_progressbar, progress_description, specific_progress_label)

    if terminateThread:
        handleShutdown()
        return
    #Print statistics into the logs

    stopAll = ms()
    progress_description['text'] = f"Prozess beendet. ({stopAll-startAll}ms)"

    totalTime = int(stopAll-startAll)
    seconds = int((totalTime/1000)%60)
    minutes = int((totalTime/(1000*60))%60)
    hours = (totalTime/(1000*60*60))%24

    addLog(f"\n\nGesamtdauer: {stopAll-startAll}ms (" + "%dh:%dm:%ds" % (hours, minutes, seconds) + ")\n")
    addLog(f"Gefundene Hashes: {totalAmountOfHashes}\n")
    addLog(f"Davon Duplikate: {totalDuplicates}\n")
    addLog(f"Anzahl MD5: {len(listOfAllMD5Hashes)}\n")
    addLog(f"Anzahl SHA-1: {len(listOfAllSHA1Hashes)}\n")
    addLog(f"Differenz: {len(listOfAllMD5Hashes) + len(listOfAllSHA1Hashes)}\n\n")
    addLog(f"Pruefsummen der Ausgabedateien (MD5):\n")
    addLog(f"{outputMD5FileName}: {MD5OutputHash}\n")
    addLog(f"{outputSHA1FileName}: {SHA1OutputHash}\n")

    del listOfAllMD5Hashes
    del listOfAllSHA1Hashes

    printLog()

def open_file_dialog():
    file_types = [
    ("All supported files", "*.zip;*.txt;*.db;*.sql;*.xlsx;*.xls"),
    ("All files", "*.*")]

    return filedialog.askopenfilenames(
        title="Füge Dateien oder Archive hinzu",
        multiple=True,
        filetypes=file_types,
    )

def show_info():
        info_text = "WHITELIST-DB v1.4 (2024)\nLKA 712\nAlexander Betke"
        root = tk.Tk()
        root.withdraw()  # Hide the main window

        top = tk.Toplevel(root)
        top.title("Info")
        top.geometry("300x100")

        label = tk.Label(top, text=info_text)
        label.pack(pady=20)

        # Keep the program running (if needed)
        root.mainloop()

def main():
    def add_files():
        selected_files = open_file_dialog()
        for file_path in selected_files:
            if file_path not in file_listbox.get(0, tk.END):
                file_listbox.insert(tk.END, file_path)

    def process():
        def addLog(text):
            progress_logs["text"] += text
            popup.geometry(f"480x{progress_logs.winfo_reqheight()+cancel_button.winfo_reqheight()+150}")

        def cancelProcessing():
            global terminateThread
            terminateThread = True

        def printLog():
            if not os.path.exists(outputDirectory):
                os.makedirs(outputDirectory)
            logFile = open(os.path.join(outputDirectory, f"{now().strftime('%H-%M-%S-%f')[:-4]}.txt"), "w")
            logFile.write(progress_logs['text'])
            
            global_progress_label.destroy()
            specific_progress_label.destroy()
            cancel_button.destroy()

        popup = tk.Toplevel()
        popup.title("Info")
        popup.resizable(False, False)

        progress_description = tk.Label(popup, text="", wraplength=400, font=("Helvetica", 14, "italic"))
        progress_description.grid(row=0, column=0, padx=20, pady=10)

        global_progressbar = ttk.Progressbar(popup, length=420, mode="determinate")
        global_progressbar.grid(row=1, column=0, padx=(20,0), pady=2)

        specific_progressbar = ttk.Progressbar(popup, length=420, mode="determinate")
        specific_progressbar.grid(row=3, column=0, padx=(20,0), pady=2)

        global_progress_label = tk.Label(popup, text="0%", font=("Helvetica", 9))
        global_progress_label.grid(row=1, column=1, padx=0)

        specific_progress_label = tk.Label(popup, text="0%", font=("Helvetica", 9))
        specific_progress_label.grid(row=3, column=1, padx=0)

        progress_logs = tk.Label(popup, text=f'{now().strftime("%H:%M:%S.%f")[:-4]}: Starte Harmonisierungsprozess...\n', wraplength=450, font=("Helvetica", 10), justify="left")
        progress_logs.grid(row=5, column=0, pady=10, padx=25)

        cancel_button = tk.Button(popup, text="Abbruch", command=cancelProcessing)
        cancel_button.grid(row=6, column=0)
        
        popup.geometry(f"480x{progress_logs.winfo_reqheight()+cancel_button.winfo_reqheight()+150}")

        Thread(target=lambda: process_files(list(file_listbox.get(0, tk.END)), fetchMD5.get(), fetchSHA1.get(), global_progressbar, specific_progressbar, global_progress_label, specific_progress_label, progress_description, lambda text: addLog(text), lambda: printLog()), args=()).start()
        popup.mainloop()

    def remove_selected():
        selected_indices = file_listbox.curselection()
        for index in reversed(selected_indices):
            file_listbox.delete(index)

    root = tk.Tk()
    root.title("WHITELIST-DB")
    root.geometry("450x600")
    root.resizable(False, False)

    fileListFrameWithButtoms = tk.Frame(root)
    fileListFrameWithButtoms.pack(expand=True, side=tk.TOP)

    fileListFrame = tk.Frame(fileListFrameWithButtoms)
    fileListFrame.pack(expand=True)

    x_scrollbar = tk.Scrollbar(fileListFrame, orient=tk.HORIZONTAL)
    x_scrollbar.pack(side=tk.BOTTOM, fill=tk.X)

    y_scrollbar = tk.Scrollbar(fileListFrame, orient=tk.VERTICAL)
    y_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    file_listbox = tk.Listbox(fileListFrame, selectmode=tk.EXTENDED, xscrollcommand=x_scrollbar.set, yscrollcommand=y_scrollbar.set, width=53, height=18, font=("Helvetica", 10, "bold"))
    file_listbox.pack(expand=True)

    # Attach the horizontal scrollbar to the listbox
    x_scrollbar.config(command=file_listbox.xview)

    # Attach the vertical scrollbar to the listbox
    y_scrollbar.config(command=file_listbox.yview)

    fileListButtomsFrame = tk.Frame(fileListFrameWithButtoms)
    fileListButtomsFrame.pack(side=tk.BOTTOM, fill=tk.X)

    file_picker_button = tk.Button(fileListButtomsFrame, text="Hinzufügen", font=("Helvetica", 12), command=add_files)
    file_picker_button.pack(side=tk.LEFT)

    remove_button = tk.Button(fileListButtomsFrame, text="Entfernen", font=("Helvetica", 12), command=remove_selected)
    remove_button.pack(side=tk.LEFT, padx=10)


    # Frame for checkboxes
    checkbox_frame = tk.Frame(root)
    checkbox_frame.pack(side=tk.LEFT, padx=(30, 0), pady=(0, 25))

    # Checkbox variables
    fetchMD5 = tk.IntVar()
    fetchSHA1 = tk.IntVar()

    #Default values
    fetchMD5.set(1)
    fetchSHA1.set(0)

    # First checkbox
    checkbox1 = tk.Checkbutton(checkbox_frame, text="MD5", font=("Helvetica", 15), variable=fetchMD5)
    checkbox1.pack(side=tk.TOP, anchor=tk.W)

    # Second checkbox
    checkbox2 = tk.Checkbutton(checkbox_frame, text="SHA-1", font=("Helvetica", 15), variable=fetchSHA1)
    checkbox2.pack(side=tk.TOP, anchor=tk.W)

    info_button = tk.Button(root, text="?", font=("Helvetica", 15,), command=show_info, height=2, width=6)
    info_button.pack(side=tk.RIGHT, padx=(0, 30), pady=(0, 25))

    process_button = tk.Button(root, text="Start", font=("Helvetica", 15, "bold"), command=process, height=2, width=15)
    process_button.pack(side=tk.LEFT, fill=tk.X, padx=10, pady=(0, 25))

    root.mainloop()

if __name__ == "__main__":
    main()
