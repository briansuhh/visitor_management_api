from django.shortcuts import render
from rest_framework.response import Response
from rest_framework.views import APIView
from drf_spectacular.utils import extend_schema
from .serializers import HealthSerializer

# Create your views here.
@extend_schema(
    tags=["Health"],
    description="Health check endpoint to verify that the application is running.",
    responses={200: HealthSerializer})
class HealthCheckView(APIView):
    def get(self, request):
        return Response({"status": "healthy"})