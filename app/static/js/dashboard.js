// Dashboard JavaScript for Phishing Email Detector

class PhishingDashboard {
    constructor() {
        this.apiBase = '/api';
        this.refreshInterval = 30000; // 30 seconds
        this.init();
    }
    
    async init() {
        console.log('🚀 Initializing Phishing Dashboard...');
        await this.loadStats();
        await this.loadRecentDetections();
        this.setupAutoRefresh();
        this.setupEventListeners();
    }
    
    async loadStats() {
        try {
            const response = await fetch(`${this.apiBase}/stats`);
            if (!response.ok) throw new Error('Failed to load stats');
            
            const data = await response.json();
            this.updateStats(data);
            this.updateCharts(data);
        } catch (error) {
            console.error('Error loading stats:', error);
            this.showError('Failed to load statistics');
        }
    }
    
    updateStats(data) {
        // Update stat cards
        document.getElementById('total-emails').textContent = data.total_analyzed;
        document.getElementById('phishing-detected').textContent = data.phishing_detected;
        document.getElementById('detection-rate').textContent = data.detection_rate + '%';
        
        // Update risk distribution
        const distribution = data.risk_distribution;
        document.getElementById('critical-count').textContent = distribution.critical;
        document.getElementById('high-count').textContent = distribution.high;
        document.getElementById('medium-count').textContent = distribution.medium;
        document.getElementById('low-count').textContent = distribution.low;
        document.getElementById('safe-count').textContent = distribution.safe;
    }
    
    updateCharts(data) {
        // Risk distribution chart
        const riskData = [{
            values: Object.values(data.risk_distribution),
            labels: Object.keys(data.risk_distribution).map(k => k.toUpperCase()),
            type: 'pie',
            marker: {
                colors: ['#fc8181', '#f6ad55', '#f6e05e', '#68d391', '#63b3ed']
            },
            textinfo: 'label+percent'
        }];
        
        Plotly.newPlot('risk-chart', riskData, {
            margin: { t: 0, b: 0, l: 0, r: 0 },
            paper_bgcolor: 'transparent'
        });
        
        // Trend chart
        if (data.trends) {
            const trendData = [{
                x: data.trends.dates || ['Day 1', 'Day 2', 'Day 3', 'Day 4', 'Day 5', 'Day 6', 'Day 7'],
                y: data.trends.last_7_days || [0, 0, 0, 0, 0, 0, 0],
                type: 'scatter',
                mode: 'lines+markers',
                name: 'Phishing Detected',
                line: { color: '#667eea', width: 3 },
                marker: { size: 8 }
            }];
            
            Plotly.newPlot('trend-chart', trendData, {
                margin: { t: 20, b: 40, l: 50, r: 20 },
                xaxis: { title: 'Date' },
                yaxis: { title: 'Count' },
                paper_bgcolor: 'transparent',
                plot_bgcolor: 'transparent'
            });
        }
    }
    
    async loadRecentDetections() {
        try {
            // In production, fetch from API
            // For demo, use sample data
            const sampleData = [
                { id: 'a1b2c3', subject: 'URGENT: Account Suspension', score: 87, level: 'CRITICAL', time: '5 min ago' },
                { id: 'd4e5f6', subject: 'Your PayPal Invoice', score: 72, level: 'HIGH', time: '12 min ago' },
                { id: 'g7h8i9', subject: 'Weekly Team Meeting', score: 12, level: 'SAFE', time: '25 min ago' }
            ];
            
            this.renderRecentDetections(sampleData);
        } catch (error) {
            console.error('Error loading recent detections:', error);
        }
    }
    
    renderRecentDetections(detections) {
        const tbody = document.getElementById('recent-detections-body');
        tbody.innerHTML = '';
        
        detections.forEach(item => {
            const row = document.createElement('tr');
            const levelClass = item.level.toLowerCase();
            row.innerHTML = `
                <td><code style="font-size: 0.75rem; background: #f0f0f0; padding: 0.2rem 0.5rem; border-radius: 4px;">${item.id}</code></td>
                <td>${this.escapeHtml(item.subject)}</td>
                <td><strong>${item.score}%</strong></td>
                <td><span class="badge badge-${levelClass}">${item.level}</span></td>
                <td style="color: #718096; font-size: 0.875rem;">${item.time}</td>
            `;
            tbody.appendChild(row);
        });
    }
    
    setupAutoRefresh() {
        setInterval(() => {
            console.log('🔄 Refreshing dashboard...');
            this.loadStats();
            this.loadRecentDetections();
        }, this.refreshInterval);
    }
    
    setupEventListeners() {
        // Manual refresh button
        const refreshBtn = document.getElementById('refresh-btn');
        if (refreshBtn) {
            refreshBtn.addEventListener('click', () => {
                this.loadStats();
                this.loadRecentDetections();
            });
        }
        
        // Analyze email form
        const form = document.getElementById('analyze-form');
        if (form) {
            form.addEventListener('submit', async (e) => {
                e.preventDefault();
                await this.analyzeEmail(form);
            });
        }
    }
    
    async analyzeEmail(form) {
        const formData = new FormData(form);
        const emailData = {
            subject: formData.get('subject'),
            sender: formData.get('sender'),
            body: formData.get('body')
        };
        
        try {
            const response = await fetch(`${this.apiBase}/analyze`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(emailData)
            });
            
            if (!response.ok) throw new Error('Analysis failed');
            
            const result = await response.json();
            this.showAnalysisResult(result);
            this.loadStats(); // Refresh stats
        } catch (error) {
            console.error('Error analyzing email:', error);
            this.showError('Failed to analyze email');
        }
    }
    
    showAnalysisResult(result) {
        const container = document.getElementById('analysis-result');
        if (!container) return;
        
        const data = result.result;
        container.innerHTML = `
            <div class="card fade-in" style="border-left: 4px solid ${this.getRiskColor(data.risk_level)};">
                <h3>Analysis Results</h3>
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 1rem; margin-top: 1rem;">
                    <div>
                        <div style="font-size: 0.875rem; color: #718096;">Risk Score</div>
                        <div style="font-size: 1.5rem; font-weight: 600;">${data.risk_score}%</div>
                    </div>
                    <div>
                        <div style="font-size: 0.875rem; color: #718096;">Risk Level</div>
                        <div><span class="badge badge-${data.risk_level.toLowerCase()}">${data.risk_level}</span></div>
                    </div>
                    <div>
                        <div style="font-size: 0.875rem; color: #718096;">Confidence</div>
                        <div style="font-size: 1.5rem; font-weight: 600;">${data.confidence}%</div>
                    </div>
                </div>
                ${data.flags.length > 0 ? `
                    <div style="margin-top: 1rem;">
                        <strong>Flags:</strong>
                        <ul style="margin-top: 0.5rem; padding-left: 1.5rem;">
                            ${data.flags.map(flag => `<li>${this.escapeHtml(flag)}</li>`).join('')}
                        </ul>
                    </div>
                ` : ''}
                ${data.recommendations.length > 0 ? `
                    <div style="margin-top: 1rem; background: #f7fafc; padding: 1rem; border-radius: 8px;">
                        <strong>Recommendations:</strong>
                        <ul style="margin-top: 0.5rem; padding-left: 1.5rem;">
                            ${data.recommendations.map(rec => `<li>${this.escapeHtml(rec)}</li>`).join('')}
                        </ul>
                    </div>
                ` : ''}
            </div>
        `;
    }
    
    getRiskColor(level) {
        const colors = {
            'CRITICAL': '#fc8181',
            'HIGH': '#f6ad55',
            'MEDIUM': '#f6e05e',
            'LOW': '#68d391',
            'SAFE': '#63b3ed'
        };
        return colors[level] || '#718096';
    }
    
    showError(message) {
        const container = document.getElementById('error-container');
        if (container) {
            container.innerHTML = `
                <div class="card" style="border-left: 4px solid #fc8181; background: #fff5f5;">
                    <strong style="color: #c53030;">⚠️ Error:</strong>
                    <span>${this.escapeHtml(message)}</span>
                </div>
            `;
            setTimeout(() => {
                container.innerHTML = '';
            }, 5000);
        }
    }
    
    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
}

// Initialize dashboard when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    new PhishingDashboard();
});
