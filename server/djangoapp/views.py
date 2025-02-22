from django.shortcuts import render, get_object_or_404, redirect
from django.http import HttpResponseRedirect, HttpResponse, JsonResponse
from django.contrib.auth.models import User
from django.contrib.auth import logout, login, authenticate
from django.contrib import messages
from django.views.decorators.csrf import csrf_exempt
from datetime import datetime
import logging
import json

from .populate import initiate
from .models import CarMake, CarModel
from .restapis import get_request, analyze_review_sentiments, post_review

# Get an instance of a logger
logger = logging.getLogger(__name__)


@csrf_exempt
def login_user(request):
    """Handles user login."""
    try:
        data = json.loads(request.body)
        username = data.get('userName', '')
        password = data.get('password', '')
        user = authenticate(username=username, password=password)
        if user is not None:
            login(request, user)
            return JsonResponse({"userName": username, "status": "Authenticated"})
        return JsonResponse({"userName": username, "status": "Failed"})
    except json.JSONDecodeError:
        return JsonResponse({"error": "Invalid JSON format"}, status=400)


@csrf_exempt
def logout_user(request):
    """Handles user logout."""
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            username = data.get("userName", "")
        except json.JSONDecodeError:
            username = ""

        logout(request)
        return JsonResponse({"userName": username, "status": "Logged out"})
    
    return JsonResponse({"error": "Invalid request method"}, status=400)


@csrf_exempt
def registration(request):
    """Handles user registration."""
    try:
        data = json.loads(request.body)
        username = data.get('userName', '')
        password = data.get('password', '')
        first_name = data.get('firstName', '')
        last_name = data.get('lastName', '')
        email = data.get('email', '')

        if User.objects.filter(username=username).exists():
            return JsonResponse({"userName": username, "error": "Already Registered"}, status=400)

        user = User.objects.create_user(
            username=username, first_name=first_name, last_name=last_name,
            password=password, email=email
        )
        login(request, user)
        return JsonResponse({"userName": username, "status": "Authenticated"})
    except json.JSONDecodeError:
        return JsonResponse({"error": "Invalid JSON format"}, status=400)


def get_cars(request):
    """Fetches all car models and car makes."""
    if CarMake.objects.count() == 0:
        initiate()
    
    car_models = CarModel.objects.select_related('car_make')
    cars = [{"CarModel": model.name, "CarMake": model.car_make.name} for model in car_models]
    
    return JsonResponse({"CarModels": cars})


def get_dealerships(request, state="All"):
    """Fetches dealerships, either all or filtered by state."""
    endpoint = "/fetchDealers" if state == "All" else f"/fetchDealers/{state}"
    dealerships = get_request(endpoint)
    
    return JsonResponse({"status": 200, "dealers": dealerships})


def get_dealer_details(request, dealer_id):
    """Fetches details of a specific dealer."""
    if dealer_id:
        endpoint = f"/fetchDealer/{dealer_id}"
        dealership = get_request(endpoint)
        return JsonResponse({"status": 200, "dealer": dealership})
    
    return JsonResponse({"status": 400, "message": "Bad Request"})


def get_dealer_reviews(request, dealer_id):
    """Fetches reviews of a dealer and analyzes their sentiments."""
    if dealer_id:
        endpoint = f"/fetchReviews/dealer/{dealer_id}"
        reviews = get_request(endpoint)
        if reviews:
            for review_detail in reviews:
                response = analyze_review_sentiments(review_detail.get('review', ''))
                review_detail['sentiment'] = response.get('sentiment', 'unknown')
        return JsonResponse({"status": 200, "reviews": reviews})
    
    return JsonResponse({"status": 400, "message": "Bad Request"})


@csrf_exempt
def add_review(request):
    """Handles adding a new review."""
    if request.user.is_authenticated:
        try:
            data = json.loads(request.body)
            response = post_review(data)
            return JsonResponse({"status": 200, "response": response})
        except json.JSONDecodeError:
            return JsonResponse({"status": 400, "message": "Invalid JSON format"})
        except Exception as e:
            return JsonResponse({"status": 500, "message": f"Error in posting review: {str(e)}"})
    
    return JsonResponse({"status": 403, "message": "Unauthorized"})
