Some of the tests files are generated using external tools

To generate AES using 7zip::

    7za a -tzip -pYOUR-PASS -mem=AES256 -mm=STORE result_file.zip source_dir_or_file
    7za a -tzip -pYOUR-PASS -mem=AES128 -mm=DEFLATE result_file.zip source_dir_or_file
    7za a -tzip -pYOUR-PASS -mem=AES192 -mm=LZMA result_file.zip source_dir_or_file
