import os
import pickle
import face_recognition
import numpy as np

directory = 'pictures'

for filename in os.listdir(directory):
    f = os.path.join(directory, filename)
    # checking if it is a file
    if os.path.isfile(f):
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




