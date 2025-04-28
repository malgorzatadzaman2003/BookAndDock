from rest_framework.serializers import ModelSerializer
from .models import Guide, Comment

class CommentSerializer(ModelSerializer):
    class Meta:
        model = Comment
        fields = ['id', 'author', 'content', 'created_at']
        read_only_fields = ['id', 'created_at']


class GuideSerializer(ModelSerializer):
    class Meta:
        model = Guide
        fields = ['id', 'title', 'description', 'created_at', 'comments']
        read_only_fields = ['id', 'created_at', 'comments']

    comments = CommentSerializer(many=True, read_only=True, source='comment_set')
