// static/js/script.js
let attackChart = null;
let severityChart = null;

function updateTime() {
    const now = new Date();
    document.getElementById('current-time').textContent = now.toLocaleString();
}

function fetchAttackEvents() {
    fetch("/api/events")
        .then(response => response.json())
        .then(data => {
            updateTable(data);
            updateStats(data);
            updateCharts(data);
        })
        .catch(error => {
            console.error("Error fetching attack events:", error);
            showNotification('Error fetching data', 'error');
        });
}

function updateTable(data) {
    const tableBody = document.getElementById("attack-events-body");
    tableBody.innerHTML = "";

    data.forEach(event => {
        const row = document.createElement("tr");
        row.innerHTML = `
            <td>${event.timestamp}</td>
            <td>${event.type}</td>
            <td class="severity-${event.severity.toLowerCase()}">${event.severity}</td>
            <td>${event.ip}</td>
            <td>${event.description}</td>
        `;
        tableBody.insertBefore(row, tableBody.firstChild);
    });
}

function updateStats(data) {
    const stats = {
        total: data.length,
        high: data.filter(e => e.severity === "High").length,
        medium: data.filter(e => e.severity === "Medium").length,
        low: data.filter(e => e.severity === "Low").length
    };

    document.getElementById("total-attacks").textContent = stats.total;
    document.getElementById("high-severity").textContent = stats.high;
    document.getElementById("medium-severity").textContent = stats.medium;
    document.getElementById("low-severity").textContent = stats.low;
}

function updateCharts(data) {
    // Destroy existing charts
    if (attackChart) attackChart.destroy();
    if (severityChart) severityChart.destroy();

    // Attack distribution
    const attackTypes = {};
    data.forEach(event => {
        attackTypes[event.type] = (attackTypes[event.type] || 0) + 1;
    });

    // Create attack distribution chart
    const attackCtx = document.getElementById("attackChart").getContext("2d");
    attackChart = new Chart(attackCtx, {
        type: "bar",
        data: {
            labels: Object.keys(attackTypes),
            datasets: [{
                label: "Number of Attacks",
                data: Object.values(attackTypes),
                backgroundColor: [
                    'rgba(239, 68, 68, 0.5)',
                    'rgba(59, 130, 246, 0.5)',
                    'rgba(34, 197, 94, 0.5)',
                    'rgba(234, 179, 8, 0.5)',
                    'rgba(168, 85, 247, 0.5)'
                ],
                borderColor: [
                    'rgb(239, 68, 68)',
                    'rgb(59, 130, 246)',
                    'rgb(34, 197, 94)',
                    'rgb(234, 179, 8)',
                    'rgb(168, 85, 247)'
                ],
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: { stepSize: 1 }
                }
            }
        }
    });

    // Severity distribution
    const severityCounts = {
        Low: data.filter(e => e.severity === "Low").length,
        Medium: data.filter(e => e.severity === "Medium").length,
        High: data.filter(e => e.severity === "High").length
    };

    const severityCtx = document.getElementById("severityChart").getContext("2d");
    severityChart = new Chart(severityCtx, {
        type: "doughnut",
        data: {
            labels: ["Low", "Medium", "High"],
            datasets: [{
                data: [severityCounts.Low, severityCounts.Medium, severityCounts.High],
                backgroundColor: [
                    'rgba(34, 197, 94, 0.5)',
                    'rgba(234, 179, 8, 0.5)',
                    'rgba(239, 68, 68, 0.5)'
                ],
                borderColor: [
                    'rgb(34, 197, 94)',
                    'rgb(234, 179, 8)',
                    'rgb(239, 68, 68)'
                ],
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { position: 'right' }
            }
        }
    });
}

function simulateAttack(type) {
    fetch(`/api/simulate/${type}`, {
        method: "POST"
    })
    .then(response => response.json())
    .then(data => {
        showNotification(`${data.message} - ${data.severity} Severity`, 'success');
        fetchAttackEvents();
    })
    .catch(error => {
        console.error("Error simulating attack:", error);
        showNotification('Error simulating attack', 'error');
    });
}

function showNotification(message, type) {
    const notification = document.getElementById('notification');
    notification.textContent = message;
    notification.className = `notification ${type}`;
    notification.style.display = 'block';

    setTimeout(() => {
        notification.style.display = 'none';
    }, 3000);
}

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    updateTime();
    setInterval(updateTime, 1000);
    fetchAttackEvents();
    setInterval(fetchAttackEvents, 30000);
});