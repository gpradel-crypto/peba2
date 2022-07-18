import os
import face_recognition
import time

directory = 'pictures'

# start the clock
start_time = time.time()
start_cpu_time = time.process_time()

cnt=0


for filename in os.listdir(directory):
    # print(filename)
    if (filename == '.gitkeep'):
        # print('I got out of the loop')
        continue
    f = os.path.join(directory, filename)
    # checking if it is a file
    if os.path.isfile(f):
        cnt += 1
        image = face_recognition.load_image_file(f)
        list_of_face_encodings = face_recognition.face_encodings(image)
        # encoding = np.array(list_of_face_encodings[0].tolist())
        encoding = list(list_of_face_encodings[0])
        # encoding.tolist()
        # format_encoding = ["{},".format(i) for i in encoding]
        file_path = "pict_arrays/encoding_"
        file_path = file_path + filename
        file_path = file_path + ".data"
        with open(file_path, 'w') as fp:
            fp.write("[")
            for i in range(len(encoding)-1):
                fp.write(f"{encoding[i]},")
            fp.write(f"{encoding[len(encoding)-1]}")
            fp.write("]")
            # pickle.dump(encoding, fp)
            # fp.writelines(encoding)
            # fp.writelines(format_encoding)

#stop the clock
end_cpu_time = time.process_time()
end_time = time.time()


#get the execution time
elapsed_time = end_time - start_time
elapsed_cpu_time = end_cpu_time - start_cpu_time

with open('results_python.data', 'w') as f:
    print('Initialisation of the database of pictures.', file=f)
    print(f'{cnt} pictures were encoded.', file=f)
    print('Execution clock time: ', elapsed_time, ' seconds', file=f)
    print('Execution CPU time: ', elapsed_cpu_time, ' seconds', file=f)


