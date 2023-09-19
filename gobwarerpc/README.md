# Example of an API implemented using Python and Flask with Gobware and gRPC

```python
from flask import Flask, request, jsonify, make_response
import grpc
from google.protobuf.json_format import MessageToDict

import gobware_pb2
import gobware_pb2_grpc


USER_ID_KEY = 'user-id'
USER_ROLE = 'user'
ROLE_KEY = 'user-role'
ACCESS_TOKEN = 'access-token'
REFRESH_TOKEN = 'refresh-token'

app = Flask(__name__)

channel = grpc.insecure_channel('localhost:5000')
stub = gobware_pb2_grpc.GobwareServiceStub(channel)


def create_token(f):
    def create_token_wrapper(*args, **kwargs):
        data = request.get_json()
        if USER_ID_KEY not in data or ROLE_KEY not in data:
            return '', 403

        req = gobware_pb2.CreateTokenRequest(data=data)
        res = stub.CreateToken(req)

        response = make_response('Token requested')
        response.set_cookie(ACCESS_TOKEN, res.encodedToken)

        return response

    return create_token_wrapper


def create_token_pair(f):
    def create_token_pair_wrapper(*args, **kwargs):
        data = request.get_json()
        if USER_ID_KEY not in data or ROLE_KEY not in data:
            return '', 403

        req = gobware_pb2.CreateTokenRequest(data=data)
        res = stub.CreateTokenPair(req)

        response = make_response('Token pair requested')
        response.set_cookie(ACCESS_TOKEN, res.encodedAccessToken)
        response.set_cookie(REFRESH_TOKEN, res.encodedRefreshToken)

        return response

    return create_token_pair_wrapper


@app.route('/request-token', methods=['GET'])
@create_token
def request_token():
    return ''


@app.route('/request-token-pair', methods=['GET'])
@create_token_pair
def request_token_pair():
    return ''


@app.route('/request-resource', methods=['GET'])
def request_resource():
    access_token = request.cookies.get(ACCESS_TOKEN)
    refresh_token = request.cookies.get(REFRESH_TOKEN)

    req = gobware_pb2.CheckAccessRequest(
        encodedToken=access_token,
        url='/request-resource',
        httpMethod=request.method
    )
    res = stub.CheckAccess(req)
    if not res.validated:
        req = gobware_pb2.CheckRefreshTokenRequest(
            encodedAccessToken=access_token,
            encodedRefreshToken=refresh_token
        )
        res = stub.CheckRefreshToken(req)
        if res.successful:
            response = make_response(
                {'message': 'Token pair requested', 'data': 'Resource'}
            )
            response.set_cookie(ACCESS_TOKEN, res.encodedAccessToken)
            response.set_cookie(REFRESH_TOKEN, res.encodedRefreshToken)
            return response, 200
        else:
            return '', 403
    elif res.validated and not res.access:
        return '', 403

    return 'Resource', 200


@app.route('/request-another-resource', methods=['GET', 'POST', 'PUT'])
def request_another_resource():
    access_token = request.cookies.get(ACCESS_TOKEN)
    refresh_token = request.cookies.get(REFRESH_TOKEN)

    req = gobware_pb2.CheckAccessRequest(
        encodedToken=access_token,
        url='/request-another-resource',
        httpMethod=request.method
    )
    res = stub.CheckAccess(req)
    if not res.access:
        return '', 403
    elif not res.validated and res.access:
        req = gobware_pb2.CheckRefreshTokenRequest(
            encodedAccessToken=access_token,
            encodedRefreshToken=refresh_token
        )
        res = stub.CheckRefreshToken(req)
        if res.successful:
            response = make_response(
                {'message': 'Token pair requested', 'data': 'Another resource'}
            )
            response.set_cookie(ACCESS_TOKEN, res.encodedAccessToken)
            response.set_cookie(REFRESH_TOKEN, res.encodedRefreshToken)
            return response, 200
        else:
            return '', 403

    return 'Another resource', 200


@app.route('/parse-token-data', methods=['GET'])
def parse_token_data():
    access_token = request.cookies.get(ACCESS_TOKEN)

    req = gobware_pb2.CheckAccessTokenRequest(encodedToken=access_token)
    res = stub.ParseTokenData(req)
    data_dict = MessageToDict(res)
    if data_dict.get('successful') is True:
        return jsonify(data_dict.get('data')), 200
    else:
        return '', 403


if __name__ == '__main__':
    req = gobware_pb2.AddACLRuleRequest(
        role=USER_ROLE, route='/request-token', httpMethods=['GET']
    )
    res = stub.AddACLRule(req)

    req = gobware_pb2.AddACLRuleRequest(
        role=USER_ROLE, route='/request-token-pair', httpMethods=['GET']
    )
    res = stub.AddACLRule(req)

    req = gobware_pb2.AddACLRuleRequest(
        role=USER_ROLE, route='/request-resource', httpMethods=['GET']
    )
    res = stub.AddACLRule(req)

    req = gobware_pb2.AddACLRuleRequest(
        role=USER_ROLE, route='/request-another-resource', httpMethods=['GET']
    )
    res = stub.AddACLRule(req)

    req = gobware_pb2.AddACLRuleRequest(
        role='', route='/request-token', httpMethods=['GET']
    )
    res = stub.AddACLRule(req)

    req = gobware_pb2.AddACLRuleRequest(
        role='', route='/request-token-pair', httpMethods=['GET']
    )
    res = stub.AddACLRule(req)

    req = gobware_pb2.AddACLRuleRequest(
        role='', route='/request-another-resource',
        httpMethods=['GET', 'POST', 'PUT']
    )
    res = stub.AddACLRule(req)

    req = gobware_pb2.AddACLRuleRequest(
        role=USER_ROLE, route='/request-another-resource', httpMethods=['PUT']
    )
    res = stub.AddACLRule(req)

    app.run(port=6200, debug=True)
