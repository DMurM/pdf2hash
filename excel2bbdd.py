import gspread
from google.oauth2.service_account import Credentials
import mysql.connector
import requests
import os
import subprocess
import glob

try:
    from pyhanko.pdf_utils.misc import PdfReadError
    from pyhanko.pdf_utils.reader import PdfFileReader
except ImportError:
    print("pyhanko is missing, run 'pip install --user pyhanko==0.20.1' to install it!")
    exit(1)

import logging
import time

logger = logging.getLogger(__name__)

class SecurityRevision:
    revisions = {
        2: 32,  # RC4_BASIC
        3: 32,  # RC4_EXTENDED
        4: 32,  # RC4_OR_AES128
        5: 48,  # AES_R5_256
        6: 48,  # AES_256
    }

    @classmethod
    def get_key_length(cls, revision):
        return cls.revisions.get(revision, 48)


class PdfHashExtractor:

    def __init__(self, file_name: str, strict: bool = False):
        self.file_name = file_name

        with open(file_name, "rb") as doc:
            self.pdf = PdfFileReader(doc, strict=strict)
            self.encrypt_dict = self.pdf._get_encryption_params()

            if not self.encrypt_dict:
                raise RuntimeError("File not encrypted")

            self.algorithm: int = self.encrypt_dict.get("/V")
            self.length: int = self.encrypt_dict.get("/Length", 40)
            self.permissions: int = self.encrypt_dict["/P"]
            self.revision: int = self.encrypt_dict["/R"]

    @property
    def document_id(self) -> bytes:
        return self.pdf.document_id[0]

    @property
    def encrypt_metadata(self) -> str:
        return str(int(self.pdf.security_handler.encrypt_metadata))

    def parse(self) -> None:
        passwords = self.get_passwords()
        fields = [
            f"$pdf${self.algorithm}",
            self.revision,
            self.length,
            self.permissions,
            self.encrypt_metadata,
            len(self.document_id),
            self.document_id.hex(),
            passwords,
        ]
        self.pdf_hash = "*".join(map(str, fields))

    def get_passwords(self) -> str:
        passwords = []
        keys = ("udata", "odata", "oeseed", "ueseed")
        max_key_length = SecurityRevision.get_key_length(self.revision)

        for key in keys:
            if data := getattr(self.pdf.security_handler, key):
                data: bytes = data[:max_key_length]
                passwords.extend([str(len(data)), data.hex()])

        return "*".join(passwords)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="PDF Hash Extractor")
    parser.add_argument(
        "pdf_files", nargs="*", help="PDF file(s) to extract information from"
    )
    parser.add_argument(
        "-d", "--debug", action="store_true", help="Print the encryption dictionary"
    )
    args = parser.parse_args()

    # Load credentials securely
    google_credentials_file = 'lostmypasswordconnection.json'  # Adjust path as needed
    scope = ['https://spreadsheets.google.com/feeds', 'https://www.googleapis.com/auth/drive']
    creds = Credentials.from_service_account_file(google_credentials_file, scopes=scope)
    client = gspread.authorize(creds)

    # Access the Google Sheet
    spreadsheet_id = '1SbbPWjiIOJXQR62Mb4KGcpS90MPUb-Ebc9T2Ss0zG-s'
    sheet = client.open_by_key(spreadsheet_id).sheet1
    values = sheet.get_all_values()

    # Setup database connection
    mydb = mysql.connector.connect(
        host=os.getenv('MYSQL_HOST', 'localhost'),
        user=os.getenv('MYSQL_USER', 'root'),
        password=os.getenv('MYSQL_PASSWORD', 'satoshi'),
        database=os.getenv('MYSQL_DATABASE', 'pdf_hashes')
    )
    cursor = mydb.cursor()

    # Define la ruta de la carpeta documentos
    folder_path = 'documentos'

    try:
        for row in values[1:]:  # Salta la fila de encabezado
            file_url = row[0]
            # Comprueba si la URL ya existe en la base de datos
            cursor.execute("SELECT COUNT(*) FROM excel_data WHERE file_url = %s", (file_url,))
            if cursor.fetchone()[0] == 0:
                cursor.execute("INSERT INTO excel_data (file_url, first_name, last_name, email, attack_type, name, file_type, payment_email, score, submitted_at, token) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)", row)
                # Realiza un commit después de cada inserción para mantener la integridad de los datos
                mydb.commit()

                # Descarga el archivo usando requests
                response = requests.get(file_url)
                if response.status_code == 200:
                    # Define la ruta completa del archivo con la carpeta documentos
                    file_name = os.path.join(folder_path, f"downloaded_{file_url.split('/')[-1]}")
                    with open(file_name, 'wb') as f:
                        f.write(response.content)
                    print(f"Descargado y guardado {file_name} exitosamente.")

                    # Extraer el hash
                    extractor = PdfHashExtractor(file_name)
                    extractor.parse()
                    pdf_hash = extractor.pdf_hash

                    # Guardar solo el hash en un archivo de texto
                    with open(f"{file_name}.txt", "w") as hash_file:
                        hash_file.write(pdf_hash)

                    # Ejecutar el comando de hashcat
                    command = f"hashcat -m 10500 -a 0 -o result {file_name}.txt rockyou.txt --potfile-disable"
                    subprocess.run(command, shell=True)

                    # Leer el resultado de hashcat desde el archivo "result"
                    with open("result", "r") as result_file:
                        result = result_file.read().split(':')[1]  # Solo la contraseña

                    # Truncar el archivo "result" para borrar su contenido
                    open("result", "w").close()

                    # Insertar solo la contraseña en la base de datos
                    cursor.execute("INSERT INTO users_result (first_name, last_name, email, file_name, attack_type, result) VALUES (%s, %s, %s, %s, %s, %s)", (row[1], row[2], row[3], os.path.basename(file_name), row[4], result))
                    mydb.commit()

                    # Enviar los datos a Google Sheets
                    sheet.insert_row(row, index=2)

                    print("Resultado de hashcat:", result)
                    # Realizar la consulta a la base de datos
                    cursor.execute("SELECT first_name, last_name, email, file_name, attack_type, result FROM users_result")
                    mysql_results = cursor.fetchall()
                    
                else:
                    print(f"Fallo al descargar desde {file_url} con código de estado {response.status_code}.")
            else:
                print(f"La URL {file_url} ya existe en la base de datos, se omite la descarga.")
    except mysql.connector.Error as e:
        print("Error de la base de datos:", e)
    except Exception as e:
        print("Se produjo un error:", e)
    finally:
        cursor.close()
        mydb.close()
        # Eliminar los archivos PDF y TXT creados
        files_to_delete = glob.glob(f"{folder_path}/*.pdf") + glob.glob(f"{folder_path}/*.pdf.txt")
        for file_to_delete in files_to_delete:
            os.remove(file_to_delete)
