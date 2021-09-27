from rest_framework import renderers
import json

from rest_framework.renderers import JSONRenderer
from rest_framework.views import exception_handler
from rest_framework import status

class UserRenderer(renderers.JSONRenderer):
    charset = 'utf-8'

    def render(self, data, accepted_media_type=None, renderer_context=None):
        response = ''
        if 'ErrorDetail' in str(data):
            response = json.dumps({'errors': data})
        else:
            response = json.dumps({'data': data})
        return response














# class UserRenderer(renderers.JSONRenderer):
#     charset = 'utf-8'
# 
#     def render(self, data, accepted_media_type, renderer_context, status_code=status.HTTP_201_CREATED):
#         response_data = {
# 
#             "data": data,
#                          "message": "User registered successfully",
#                           "status": "success",
#                          'statusCode':status_code,
# 
#                          }
#         # response = super(UserRenderer, self).render(
#         #     response_data,accepted_media_type,renderer_context
#         # )
#         if 'ErrorDetail' in str(data):
#             response = json.dumps({'errors': data})
#         else:
#             response = super(UserRenderer, self).render(
#                 response_data, accepted_media_type, renderer_context)
#              # response = json.dumps({'data': data})
#         return response
# 
# 
# 
#         # if 'ErrorDetail' in str(data):
#         #     response = json.dumps({'errors': data})
#         # else:
#         #     response = json.dumps({'data': data})
#         # return response
