from django.shortcuts import render
from rest_framework.response import Response
from rest_framework.views import APIView
from drf_spectacular.utils import extend_schema

# Create your views here.
@extend_schema(tags=["Health"])
class HealthCheckView(APIView):
    def get(self, request):
        return Response({"status": "healthy"})