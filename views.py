from django.shortcuts import render, redirect
from django.contrib.auth import login, authenticate, logout  # Add logout to imports
from django.contrib import messages
from .forms import (
    RegistrationForm, OTPVerificationForm,
    ForgotPasswordForm, ResetPasswordForm  # Add these imports
)
from .models import User
from .models import User, JobApplication, Resume, JobAlert, Job, SavedJob  # Add missing models
import random
import string
from django.utils import timezone
from django.core.mail import send_mail
from django.contrib.auth.decorators import login_required, user_passes_test  # Add user_passes_test here
from django.http import HttpResponse
from django.shortcuts import get_object_or_404
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.forms import PasswordChangeForm
from django.core.files.storage import FileSystemStorage
from django.conf import settings
from .models import User, JobApplication, Resume  # Add Resume here
import os

def generate_otp():
    return ''.join(random.choices(string.digits, k=6))

def register(request):
    if request.method == 'POST':
        form = RegistrationForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.otp = generate_otp()
            user.otp_created_at = timezone.now()
            user.save()
            
            # Send OTP email
            subject = 'Email Verification OTP'
            message = f'Your OTP for email verification is: {user.otp}'
            from_email = 'your-email@gmail.com'  # Replace with your email
            recipient_list = [user.email]
            
            try:
                send_mail(subject, message, from_email, recipient_list)
                messages.success(request, 'OTP has been sent to your email.')
                return redirect('verify_otp', user_id=user.id)
            except Exception as e:
                user.delete()
                messages.error(request, 'Failed to send OTP. Please try again.')
                
    else:
        form = RegistrationForm()
    return render(request, 'accounts/register.html', {'form': form})

def verify_otp(request, user_id):
    user = User.objects.get(id=user_id)
    
    if request.method == 'POST':
        form = OTPVerificationForm(request.POST)
        if form.is_valid():
            if form.cleaned_data['otp'] == user.otp:
                user.email_verified = True
                user.save()
                # Specify the authentication backend
                login(request, user, backend='django.contrib.auth.backends.ModelBackend')
                messages.success(request, 'Email verified successfully!')
                return redirect('home')
            else:
                messages.error(request, 'Invalid OTP')
    else:
        form = OTPVerificationForm()
    
    return render(request, 'accounts/verify_otp.html', {'form': form})


def forgot_password(request):
    if request.method == 'POST':
        form = ForgotPasswordForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            try:
                user = User.objects.get(email=email)
                user.otp = generate_otp()
                user.otp_created_at = timezone.now()
                user.save()
                
                # Send OTP email
                subject = 'Password Reset OTP'
                message = f'Your OTP for password reset is: {user.otp}'
                from_email = 'your-email@gmail.com'  # Replace with your email
                recipient_list = [email]
                
                send_mail(subject, message, from_email, recipient_list)
                messages.success(request, 'OTP has been sent to your email.')
                return redirect('reset_password', user_id=user.id)
            except User.DoesNotExist:
                messages.error(request, 'Email not found')
    else:
        form = ForgotPasswordForm()
    return render(request, 'accounts/forgot_password.html', {'form': form})

def reset_password(request, user_id):
    user = User.objects.get(id=user_id)
    
    if request.method == 'POST':
        form = ResetPasswordForm(request.POST)
        if form.is_valid():
            if form.cleaned_data['password1'] == form.cleaned_data['password2']:
                user.set_password(form.cleaned_data['password1'])
                user.save()
                messages.success(request, 'Password reset successfully!')
                return redirect('login')
            else:
                messages.error(request, 'Passwords do not match')
    else:
        form = ResetPasswordForm()
    return render(request, 'accounts/reset_password.html', {'form': form})


def user_login(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)
        
        if user is not None:
            if user.email_verified:
                login(request, user)
                messages.success(request, 'Login successful!')
                return redirect('home')
            else:
                messages.error(request, 'Please verify your email first.')
        else:
            messages.error(request, 'Invalid username or password.')
    
    return render(request, 'accounts/login.html')


def user_logout(request):
    logout(request)
    messages.success(request, 'You have been logged out successfully.')
    return redirect('login')

def home(request):
    # Get some statistics for the homepage
    total_jobs = Job.objects.filter(is_active=True).count()
    total_companies = Job.objects.values('company').distinct().count()
    recent_jobs = Job.objects.filter(is_active=True).order_by('-posted_date')[:6]
    
    context = {
        'total_jobs': total_jobs,
        'total_companies': total_companies,
        'recent_jobs': recent_jobs,
    }
    return render(request, 'accounts/home.html', context)

# Move this to the top after imports
def is_recruiter(user):
    return user.user_type == 'recruiter' if hasattr(user, 'user_type') else False

# Update the dashboard view
@login_required
def dashboard(request):
    context = {}
    
    if hasattr(request.user, 'user_type') and request.user.user_type == 'recruiter':
        # Get recruiter's posted jobs
        posted_jobs = Job.objects.filter(recruiter=request.user).order_by('-posted_date')
        total_applications = JobApplication.objects.filter(job__recruiter=request.user).count()
        context.update({
            'posted_jobs': posted_jobs[:5],  # Show last 5 posted jobs
            'total_jobs': posted_jobs.count(),
            'total_applications': total_applications,
            'is_recruiter': True,  # Add this flag for template
        })
    else:
        # For job seekers
        available_jobs = Job.objects.filter(is_active=True).order_by('-posted_date')[:5]
        applied_jobs = JobApplication.objects.filter(applicant=request.user).select_related('job')
        saved_jobs = SavedJob.objects.filter(user=request.user).select_related('job')
        context.update({
            'available_jobs': available_jobs,
            'applied_jobs': applied_jobs[:5],
            'saved_jobs': saved_jobs[:5],
            'is_recruiter': False,  # Add this flag for template
        })
    
    return render(request, 'accounts/dashboard.html', context)

@login_required
def profile(request):
    return render(request, 'accounts/profile.html')

@login_required
def update_profile(request):
    if request.method == 'POST':
        # Handle profile update
        pass
    return render(request, 'accounts/update_profile.html')

@login_required
def change_password(request):
    if request.method == 'POST':
        form = PasswordChangeForm(request.user, request.POST)
        if form.is_valid():
            user = form.save()
            update_session_auth_hash(request, user)
            messages.success(request, 'Your password was successfully updated!')
            return redirect('dashboard')
        else:
            messages.error(request, 'Please correct the error below.')
    else:
        form = PasswordChangeForm(request.user)
    return render(request, 'accounts/change_password.html', {'form': form})

@login_required
def my_resume(request):
    if request.method == 'POST' and request.FILES.get('resume'):
        uploaded_file = request.FILES['resume']
        fs = FileSystemStorage()
        
        # Create user-specific directory
        user_directory = f'resumes/{request.user.username}'
        if not os.path.exists(os.path.join(settings.MEDIA_ROOT, user_directory)):
            os.makedirs(os.path.join(settings.MEDIA_ROOT, user_directory))
        
        # Save the file
        filename = fs.save(f'{user_directory}/{uploaded_file.name}', uploaded_file)
        
        # Create or update Resume
        Resume.objects.update_or_create(
            user=request.user,
            defaults={'file': filename}
        )
        
        messages.success(request, 'Resume uploaded successfully!')
        return redirect('my_resume')
    
    # Get current resume if exists
    current_resume = Resume.objects.filter(user=request.user).first()
    return render(request, 'accounts/my_resume.html', {'current_resume': current_resume})

@login_required
def download_resume(request):
    try:
        resume = Resume.objects.get(user=request.user)
        if resume and resume.file:
            with open(resume.file.path, 'rb') as file:
                response = HttpResponse(file.read(), content_type='application/pdf')
                response['Content-Disposition'] = f'attachment; filename="{os.path.basename(resume.file.name)}"'
                return response
    except Resume.DoesNotExist:
        messages.error(request, 'Resume not found.')
    return redirect('my_resume')
    file_url = fs.url(filename)
    
    # Create or update JobApplication
    JobApplication.objects.update_or_create(
        applicant=request.user,
        defaults={'resume': filename}
    )
    
    messages.success(request, 'Resume uploaded successfully!')
    return redirect('my_resume')
    
    # Get current resume if exists
    current_resume = JobApplication.objects.filter(applicant=request.user).first()
    return render(request, 'accounts/my_resume.html', {'current_resume': current_resume})

@login_required
def download_resume(request):
    try:
        application = request.user.jobapplication_set.first()
        if application and application.resume:
            with open(application.resume.path, 'rb') as resume:
                response = HttpResponse(resume.read(), content_type='application/pdf')
                response['Content-Disposition'] = f'attachment; filename="{os.path.basename(application.resume.name)}"'
                return response
    except Exception as e:
        messages.error(request, 'Resume not found.')
    return redirect('my_resume')

@login_required
def saved_jobs(request):
    saved_jobs = SavedJob.objects.filter(user=request.user).select_related('job')
    return render(request, 'accounts/saved_jobs.html', {'saved_jobs': saved_jobs})

@login_required
def applied_jobs(request):
    applications = JobApplication.objects.filter(applicant=request.user).select_related('job')
    # Get list of saved job IDs for the current user
    saved_job_ids = SavedJob.objects.filter(user=request.user).values_list('job_id', flat=True)
    
    context = {
        'applications': applications,
        'saved_job_ids': saved_job_ids,
    }
    return render(request, 'accounts/applied_jobs.html', context)

@login_required
def create_job_alert(request):
    if request.method == 'POST':
        keywords = request.POST.get('keywords')
        location = request.POST.get('location')
        JobAlert.objects.create(
            user=request.user,
            keywords=keywords,
            location=location
        )
        messages.success(request, 'Job alert created successfully!')
        return redirect('job_alerts')
    return render(request, 'accounts/create_job_alert.html')

@login_required
def job_alerts(request):
    alerts = JobAlert.objects.filter(user=request.user)
    return render(request, 'accounts/job_alerts.html', {'alerts': alerts})

@login_required
def delete_job_alert(request, alert_id):
    if request.method == 'POST':
        alert = get_object_or_404(JobAlert, id=alert_id, user=request.user)
        alert.delete()
        messages.success(request, 'Job alert deleted successfully!')
    return redirect('job_alerts')

@login_required
def job_list(request):
    jobs = Job.objects.filter(is_active=True).order_by('-posted_date')
    recommended_jobs = []
    
    # Get saved jobs for the current user
    saved_job_ids = SavedJob.objects.filter(user=request.user).values_list('job_id', flat=True)
    
    if request.user.is_authenticated and request.user.user_type == 'candidate':
        # Get user's job alerts keywords
        alerts = JobAlert.objects.filter(user=request.user)
        keywords = [alert.keywords for alert in alerts]
        
        # Filter jobs based on keywords
        from django.db.models import Q
        query = Q()
        for keyword in keywords:
            query |= (
                Q(title__icontains=keyword) |
                Q(description__icontains=keyword) |
                Q(requirements__icontains=keyword)
            )
        if query:
            recommended_jobs = Job.objects.filter(query, is_active=True)
    
    return render(request, 'accounts/job_list.html', {
        'jobs': jobs,
        'recommended_jobs': recommended_jobs,
        'saved_job_ids': saved_job_ids,  # Add this to context
    })

@login_required
def save_job(request, job_id):
    job = get_object_or_404(Job, id=job_id)
    saved_job, created = SavedJob.objects.get_or_create(job=job, user=request.user)
    
    if not created:
        saved_job.delete()
        messages.success(request, 'Job removed from saved jobs.')
    else:
        messages.success(request, 'Job saved successfully!')
    
    # Return to the previous page
    next_page = request.GET.get('next', 'job_list')
    return redirect(next_page)


@login_required
@user_passes_test(lambda u: is_recruiter(u))
def create_job(request):
    if request.method == 'POST':
        title = request.POST.get('title')
        company = request.POST.get('company')
        location = request.POST.get('location')
        description = request.POST.get('description')
        requirements = request.POST.get('requirements')
        salary = request.POST.get('salary')
        deadline = request.POST.get('deadline')
        
        job = Job.objects.create(
            title=title,
            company=company,
            location=location,
            description=description,
            requirements=requirements,
            salary=salary,
            deadline=deadline,
            recruiter=request.user
        )
        messages.success(request, 'Job posted successfully!')
        return redirect('manage_jobs')
    
    return render(request, 'accounts/create_job.html')

@login_required
@user_passes_test(is_recruiter)
def edit_job(request, job_id):
    job = get_object_or_404(Job, id=job_id, recruiter=request.user)
    
    if request.method == 'POST':
        job.title = request.POST.get('title')
        job.company = request.POST.get('company')
        job.location = request.POST.get('location')
        job.description = request.POST.get('description')
        job.requirements = request.POST.get('requirements')
        job.salary = request.POST.get('salary')
        job.deadline = request.POST.get('deadline')
        job.save()
        
        messages.success(request, 'Job updated successfully!')
        return redirect('manage_jobs')
    
    return render(request, 'accounts/edit_job.html', {'job': job})

@login_required
@user_passes_test(is_recruiter)
def manage_jobs(request):
    jobs = Job.objects.filter(recruiter=request.user).order_by('-posted_date')
    saved_job_ids = SavedJob.objects.filter(user=request.user).values_list('job_id', flat=True)
    return render(request, 'accounts/manage_jobs.html', {
        'jobs': jobs,
        'saved_job_ids': saved_job_ids
    })


@login_required
def apply_job(request, job_id):
    job = get_object_or_404(Job, id=job_id)
    
    # Check if user has already applied
    if JobApplication.objects.filter(job=job, applicant=request.user).exists():
        messages.warning(request, 'You have already applied for this job.')
        return redirect('job_details', job_id=job_id)
    
    # Check if user has a resume
    resume = Resume.objects.filter(user=request.user).first()
    if not resume:
        messages.error(request, 'Please upload your resume before applying.')
        return redirect('my_resume')
    
    # Create job application
    JobApplication.objects.create(
        job=job,
        applicant=request.user,
        resume=resume.file,
        status='pending'
    )
    
    messages.success(request, 'Application submitted successfully!')
    return redirect('job_details', job_id=job_id)

@login_required
def job_details(request, job_id):
    job = get_object_or_404(Job, id=job_id)
    is_applied = JobApplication.objects.filter(job=job, applicant=request.user).exists()
    is_saved = SavedJob.objects.filter(job=job, user=request.user).exists()
    
    context = {
        'job': job,
        'is_applied': is_applied,
        'is_saved': is_saved,
    }
    
    return render(request, 'accounts/job_details.html', context)
