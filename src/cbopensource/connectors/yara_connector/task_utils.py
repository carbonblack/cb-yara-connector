import io
import os
import zipfile

import requests
from encodings import cp437

cp437encoding = cp437

def lookup_binary_by_hash(hsum, url, token, timeout=30):
    headers = {"X-Auth-Token": token}
    request_url = f"{url}/api/v1/binary/{hsum}"
    response = requests.get(
        request_url,
        headers=headers,
        stream=True,
        verify=False,
        timeout=timeout,
    )
    if response:
        with zipfile.ZipFile(io.BytesIO(response.content)) as the_binary_zip:
            # the response contains module in 'filedata'
            fp = the_binary_zip.open("filedata")
            the_binary_zip.close()
            return fp
    else:
        # otherwise return None which will be interpreted correctly in analyze_binary as haven failed to lookup the hash
        return None


def lookup_local_module(md5_up, module_store_path):
    filepath = os.path.join(module_store_path, md5_up[0:3], md5_up[3:6], md5_up + ".zip")
    if os.path.exists(filepath):
        with zipfile.ZipFile(filepath) as the_binary_zip:
            fp = the_binary_zip.open("filedata")
            the_binary_zip.close()
            return fp
    return None
