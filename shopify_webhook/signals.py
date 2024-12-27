from django.db.models.signals import post_save
from django.dispatch import receiver
from common.djangoapps.student.models.course_enrollment import CourseEnrollmentAllowed
from .models import CourseEnrollmentAllowedMode


@receiver(post_save, sender=CourseEnrollmentAllowed)
def course_enrollment_updated(sender, instance, **kwargs):
    # Custom logic when CourseEnrollmentAllowed is updated
    print(f'CourseEnrollmentAllowed updated: {instance}')
    
