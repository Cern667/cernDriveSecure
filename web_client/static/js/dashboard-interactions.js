/**
 * CernCloud Dashboard Interactions
 */

document.addEventListener('DOMContentLoaded', () => {
    // Initialize Lucide Icons
    if (window.lucide) {
        lucide.createIcons();
    }

    // Initialize Tooltips (if any)
    initTooltips();

    // Initialize Charts (if on logs page)
    if (document.getElementById('logsChart')) {
        initLogsChart();
    }
});

/**
 * Initialize Logs Chart using Chart.js
 */
function initLogsChart() {
    const ctx = document.getElementById('logsChart').getContext('2d');

    // Gradient for the chart
    const gradient = ctx.createLinearGradient(0, 0, 0, 400);
    gradient.addColorStop(0, 'rgba(0, 112, 243, 0.5)');
    gradient.addColorStop(1, 'rgba(0, 112, 243, 0.0)');

    new Chart(ctx, {
        type: 'line',
        data: {
            labels: ['00:00', '04:00', '08:00', '12:00', '16:00', '20:00', '23:59'],
            datasets: [{
                label: 'Activité Système',
                data: [12, 19, 3, 5, 2, 3, 10], // Mock data
                borderColor: '#0070F3',
                backgroundColor: gradient,
                borderWidth: 2,
                pointBackgroundColor: '#0070F3',
                pointBorderColor: '#fff',
                pointHoverBackgroundColor: '#fff',
                pointHoverBorderColor: '#0070F3',
                fill: true,
                tension: 0.4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: false
                },
                tooltip: {
                    mode: 'index',
                    intersect: false,
                    backgroundColor: 'rgba(15, 17, 21, 0.9)',
                    titleColor: '#fff',
                    bodyColor: '#A0AEC0',
                    borderColor: 'rgba(255,255,255,0.1)',
                    borderWidth: 1
                }
            },
            scales: {
                x: {
                    grid: {
                        color: 'rgba(255, 255, 255, 0.05)',
                        drawBorder: false
                    },
                    ticks: {
                        color: '#A0AEC0'
                    }
                },
                y: {
                    grid: {
                        color: 'rgba(255, 255, 255, 0.05)',
                        drawBorder: false
                    },
                    ticks: {
                        color: '#A0AEC0',
                        beginAtZero: true
                    }
                }
            },
            interaction: {
                mode: 'nearest',
                axis: 'x',
                intersect: false
            }
        }
    });
}

/**
 * Simple Tooltip Implementation
 */
function initTooltips() {
    const triggers = document.querySelectorAll('[data-tooltip]');

    triggers.forEach(trigger => {
        trigger.addEventListener('mouseenter', e => {
            const text = e.target.getAttribute('data-tooltip');
            showTooltip(e.target, text);
        });

        trigger.addEventListener('mouseleave', () => {
            hideTooltip();
        });
    });
}

let tooltipEl = null;

function showTooltip(target, text) {
    if (!tooltipEl) {
        tooltipEl = document.createElement('div');
        tooltipEl.className = 'custom-tooltip glass';
        tooltipEl.style.position = 'absolute';
        tooltipEl.style.padding = '6px 10px';
        tooltipEl.style.borderRadius = '4px';
        tooltipEl.style.fontSize = '12px';
        tooltipEl.style.color = 'white';
        tooltipEl.style.pointerEvents = 'none';
        tooltipEl.style.zIndex = '1000';
        tooltipEl.style.opacity = '0';
        tooltipEl.style.transition = 'opacity 0.2s';
        document.body.appendChild(tooltipEl);
    }

    tooltipEl.textContent = text;
    const rect = target.getBoundingClientRect();

    tooltipEl.style.top = `${rect.top - 35}px`;
    tooltipEl.style.left = `${rect.left + (rect.width / 2) - (tooltipEl.offsetWidth / 2)}px`;
    tooltipEl.style.opacity = '1';
}

function hideTooltip() {
    if (tooltipEl) {
        tooltipEl.style.opacity = '0';
    }
}
