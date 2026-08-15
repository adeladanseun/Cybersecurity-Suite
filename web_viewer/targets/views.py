"""
Views for target management
"""

import csv
import io
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import JsonResponse
from django.db.models import Q, Count
from django.views.generic import ListView, DetailView, CreateView, UpdateView, DeleteView
from django.urls import reverse_lazy
from django.contrib.auth.mixins import LoginRequiredMixin, UserPassesTestMixin

from .models import Target, TargetGroup, Project
from .forms import TargetForm, TargetImportForm, TargetGroupForm, ProjectForm


class TargetListView(LoginRequiredMixin, ListView):
    """List all targets"""
    model = Target
    template_name = 'targets/target_list.html'
    context_object_name = 'targets'
    paginate_by = 20
    
    def get_queryset(self):
        queryset = Target.objects.filter(is_active=True)
        
        # Search
        search = self.request.GET.get('search', '')
        if search:
            queryset = queryset.filter(
                Q(name__icontains=search) |
                Q(address__icontains=search) |
                Q(description__icontains=search)
            )
        
        # Filter by type
        target_type = self.request.GET.get('type', '')
        if target_type:
            queryset = queryset.filter(type=target_type)
        
        # Filter by priority
        priority = self.request.GET.get('priority', '')
        if priority:
            queryset = queryset.filter(priority=priority)
        
        return queryset.order_by('name')
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['total_targets'] = Target.objects.filter(is_active=True).count()
        context['target_types'] = Target.TYPE_CHOICES
        context['priorities'] = Target.PRIORITY_CHOICES
        context['current_filters'] = {
            'search': self.request.GET.get('search', ''),
            'type': self.request.GET.get('type', ''),
            'priority': self.request.GET.get('priority', ''),
        }
        return context


class TargetDetailView(LoginRequiredMixin, DetailView):
    """View target details"""
    model = Target
    template_name = 'targets/target_detail.html'
    context_object_name = 'target'
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        target = self.get_object()
        context['groups'] = target.groups.all()
        context['projects'] = target.projects.all()
        context['scans'] = target.scans.all()[:10]
        return context


class TargetCreateView(LoginRequiredMixin, CreateView):
    """Create new target"""
    model = Target
    form_class = TargetForm
    template_name = 'targets/target_form.html'
    success_url = reverse_lazy('targets:list')
    
    def form_valid(self, form):
        form.instance.created_by = self.request.user
        messages.success(self.request, f'Target "{form.instance.name}" created successfully.')
        return super().form_valid(form)


class TargetUpdateView(LoginRequiredMixin, UserPassesTestMixin, UpdateView):
    """Update target"""
    model = Target
    form_class = TargetForm
    template_name = 'targets/target_form.html'
    success_url = reverse_lazy('targets:list')
    
    def test_func(self):
        target = self.get_object()
        return self.request.user == target.created_by or self.request.user.is_staff
    
    def form_valid(self, form):
        messages.success(self.request, f'Target "{form.instance.name}" updated successfully.')
        return super().form_valid(form)


class TargetDeleteView(LoginRequiredMixin, UserPassesTestMixin, DeleteView):
    """Delete target"""
    model = Target
    template_name = 'targets/target_confirm_delete.html'
    success_url = reverse_lazy('targets:list')
    
    def test_func(self):
        target = self.get_object()
        return self.request.user == target.created_by or self.request.user.is_staff
    
    def delete(self, request, *args, **kwargs):
        target = self.get_object()
        messages.success(request, f'Target "{target.name}" deleted.')
        return super().delete(request, *args, **kwargs)


@login_required
def import_targets(request):
    """Import targets from file"""
    if request.method == 'POST':
        form = TargetImportForm(request.POST, request.FILES)
        
        if form.is_valid():
            file = request.FILES['file']
            target_type = form.cleaned_data.get('target_type', '')
            priority = form.cleaned_data.get('priority', 'medium')
            group_name = form.cleaned_data.get('group_name', '')
            
            # Parse file
            targets_created = 0
            targets_skipped = 0
            errors = []
            
            try:
                # Decode file content
                content = file.read().decode('utf-8')
                
                # Create group if specified
                group = None
                if group_name:
                    group, _ = TargetGroup.objects.get_or_create(
                        name=group_name,
                        created_by=request.user
                    )
                
                # Process each line
                for line in content.splitlines():
                    line = line.strip()
                    
                    # Skip empty lines and comments
                    if not line or line.startswith('#'):
                        continue
                    
                    # Handle CSV format (name,address)
                    if ',' in line and not line.startswith('http'):
                        parts = line.split(',')
                        if len(parts) >= 2:
                            name = parts[0].strip()
                            address = parts[1].strip()
                        else:
                            address = line
                            name = address
                    else:
                        address = line
                        name = address
                    
                    # Validate address
                    from core.validator import classify_target
                    if classify_target(address) == 'unknown':
                        errors.append(f"Invalid target: {address}")
                        targets_skipped += 1
                        continue
                    
                    # Check for duplicates
                    if Target.objects.filter(address=address, created_by=request.user).exists():
                        targets_skipped += 1
                        continue
                    
                    # Create target
                    target = Target.objects.create(
                        name=name,
                        address=address,
                        type=target_type or None,
                        priority=priority,
                        created_by=request.user
                    )
                    
                    # Add to group if specified
                    if group:
                        group.targets.add(target)
                    
                    targets_created += 1
            
            except Exception as e:
                messages.error(request, f'Import failed: {str(e)}')
                return redirect('targets:import')
            
            # Show results
            if targets_created > 0:
                messages.success(request, f'Successfully imported {targets_created} targets.')
            
            if targets_skipped > 0:
                messages.warning(request, f'Skipped {targets_skipped} targets (invalid or duplicates).')
            
            if errors:
                for error in errors[:5]:
                    messages.error(request, error)
            
            return redirect('targets:list')
    else:
        form = TargetImportForm()
    
    return render(request, 'targets/target_import.html', {'form': form})


class ProjectListView(LoginRequiredMixin, ListView):
    """List all projects"""
    model = Project
    template_name = 'targets/project_list.html'
    context_object_name = 'projects'
    
    def get_queryset(self):
        return Project.objects.filter(
            Q(created_by=self.request.user) |
            Q(members=self.request.user)
        ).distinct()


class ProjectDetailView(LoginRequiredMixin, DetailView):
    """View project details"""
    model = Project
    template_name = 'targets/project_detail.html'
    context_object_name = 'project'
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        project = self.get_object()
        context['targets'] = project.targets.all()
        context['members'] = project.members.all()
        context['completion'] = project.get_completion_percentage()
        return context


class ProjectCreateView(LoginRequiredMixin, CreateView):
    """Create new project"""
    model = Project
    form_class = ProjectForm
    template_name = 'targets/project_form.html'
    success_url = reverse_lazy('targets:project_list')
    
    def form_valid(self, form):
        form.instance.created_by = self.request.user
        messages.success(self.request, f'Project "{form.instance.name}" created.')
        return super().form_valid(form)


@login_required
def api_target_list(request):
    """API endpoint for targets (AJAX)"""
    targets = Target.objects.filter(is_active=True).values(
        'id', 'name', 'address', 'type', 'priority', 'last_scanned'
    )
    return JsonResponse(list(targets), safe=False)
