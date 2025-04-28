from rest_framework import mixins, permissions
from rest_framework.viewsets import ModelViewSet, GenericViewSet

from BookAndDock.models import Guide
from BookAndDock.serializers import GuideSerializer


class RecipeViewSet(ModelViewSet):
    queryset = Guide.objects.prefetch_related('comment_set').order_by('created_at')
    serializer_class = GuideSerializer
    permission_classes = [permissions.IsAuthenticatedOrReadOnly]
