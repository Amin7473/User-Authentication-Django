from rest_framework.response import Response
from rest_framework import status


class ResponseMixin(object):
    def sendresponse(self, status_code, msg, requeststatus=1, data=None, **kwargs):
        if data is None:
            return Response(
                {"message": msg, "requeststatus": requeststatus, **kwargs},
                status=status_code,
            )
        return Response(
            {"data": data, "message": msg, "requeststatus": requeststatus, **kwargs},
            status=status_code,
        )
