import logging
import os

try:
    import simplejson as json
except ImportError:
    import json

from flask import Flask, request, make_response, Response
from cStringIO import StringIO
import zipfile


def get_mocked_server(binary_directory):
    mocked_cb_server = Flask('cb')

    files = os.listdir(binary_directory)

    @mocked_cb_server.route('/api/v1/binary', methods=['GET', 'POST'])
    def binary_search_endpoint():
        if request.method == 'GET':
            query_string = request.args.get('q', '')
            rows = int(request.args.get('rows', 10))
            start = int(request.args.get('start', 0))
        elif request.method == 'POST':
            parsed_data = json.loads(request.data)
            if 'q' in parsed_data:
                query_string = parsed_data['q']
            else:
                query_string = ''

            if 'rows' in parsed_data:
                rows = int(parsed_data['rows'])
            else:
                rows = 10

            if 'start' in parsed_data:
                start = int(parsed_data['start'])
            else:
                start = 0
        else:
            return make_response('Invalid Request', 500)

        return Response(response=json.dumps(binary_search(query_string, rows, start)),
                        mimetype='application/json')

    def binary_search(q, rows, start):
        return {
            'results':
                [json.load(open(os.path.join(binary_directory, fn), 'r')) for fn in files[start:start+rows]],
            'terms': '',
            'total_results': len(files),
            'start': start,
            'elapsed': 0.1,
            'highlights': [],
            'facets': {}
        }

    @mocked_cb_server.route('/api/v1/binary/<md5sum>/summary')
    def get_binary_summary(md5sum):
        filepath = os.path.join(binary_directory, '%s.json' % md5sum.lower())
        if not os.path.exists(filepath):
            return Response("File not found", 404)

        binary_data = open(filepath, 'r').read()
        return Response(response=binary_data, mimetype='application/json')

    @mocked_cb_server.route('/api/v1/binary/<md5sum>')
    def get_binary(md5sum):
        metadata_filepath = os.path.join(binary_directory, '%s.json' % md5sum.lower())
        content_filepath = os.path.join(binary_directory, '%s' % md5sum.lower())

        for filepath in [metadata_filepath, content_filepath]:
            if not os.path.exists(filepath):
                return Response("File not found", 404)

        zipfile_contents = StringIO()
        zf = zipfile.ZipFile(zipfile_contents, 'w', zipfile.ZIP_DEFLATED, False)
        zf.writestr('filedata', open(content_filepath, 'r').read())
        zf.writestr('metadata', open(metadata_filepath, 'r').read())
        zf.close()

        return Response(response=zipfile_contents.getvalue(), mimetype='application/zip')

    @mocked_cb_server.route('/api/info')
    def info():
        return Response(response=json.dumps({"version": "5.1.0"}), mimetype='application/json')

    return mocked_cb_server


if __name__ == '__main__':
    mydir = os.path.dirname(os.path.abspath(__file__))
    binaries_dir = os.path.join(mydir, '..', 'data', 'binary_data')

    mock_server = get_mocked_server(binaries_dir)
    mock_server.run('127.0.0.1', 7982, debug=True)
