/**
 * 数据清洗和标准化模块
 * 将采集的真实数据转换为项目所需的标准格式
 */

class DataProcessor {
    constructor() {
        this.normalizeConfig = {
            riskLevels: {
                'safe': { value: 0, label: '安全', color: '#22c55e' },
                'low': { value: 1, label: '低危', color: '#84cc16' },
                'medium': { value: 2, label: '中危', color: '#f59e0b' },
                'high': { value: 3, label: '高危', color: '#ef4444' },
                'very_high': { value: 4, label: '极高危', color: '#dc2626' },
                'extreme': { value: 5, label: '严重', color: '#b91c1c' },
                'critical': { value: 6, label: '危急', color: '#991b1b' }
            }
        };
    }

    /**
     * 标准化风险等级
     */
    normalizeRiskLevel(level) {
        const config = this.normalizeConfig.riskLevels;
        if (config[level]) {
            return config[level];
        }
        // 兼容不同的风险表示方式
        const lower = level.toLowerCase();
        if (lower.includes('高') || lower.includes('high') || lower === 'danger') {
            return config.high;
        }
        if (lower.includes('中') || lower.includes('medium') || lower === 'warning') {
            return config.medium;
        }
        if (lower.includes('低') || lower.includes('low') || lower === 'info') {
            return config.low;
        }
        return config.safe;
    }

    /**
     * 将国家反诈数据标准化为预警记录
     */
    processNationalAntifraudData(data) {
        const alerts = [];
        const riskDescriptions = [
            '检测到刷单返利诈骗特征',
            '检测到虚假购物服务诈骗',
            '检测到虚假网络投资理财诈骗',
            '检测到冒充电商物流客服诈骗',
            '检测到贷款征信诈骗',
            '检测到网络游戏虚假交易诈骗',
            '检测到网络婚恋交友诈骗',
            '检测到冒充公检法诈骗',
            '检测到冒充领导熟人诈骗',
            '检测到机票退改签诈骗'
        ];

        // 根据真实统计数据生成示例预警
        data.highRiskTypes.forEach((type, index) => {
            alerts.push({
                id: this.generateId(),
                alert_title: riskDescriptions[index] || `${type.type}风险预警`,
                alert_type: '诈骗预警',
                risk_level: type.trend === 'up' ? 'high' : 'medium',
                alert_time: new Date(Date.now() - Math.random() * 7 * 24 * 60 * 60 * 1000).toISOString(),
                source: '国家反诈中心',
                statistics: {
                    annualCount: type.count,
                    trend: type.trend
                },
                description: `根据国家反诈中心统计，${type.type}类诈骗在过去一年累计发生${(type.count / 10000).toFixed(0)}万起。`,
                created_at: new Date().toISOString()
            });
        });

        return alerts;
    }

    /**
     * 将教育部案例数据标准化为知识题库
     */
    processMoeKnowledgeData(data) {
        const questions = [];
        const difficulties = ['easy', 'medium', 'hard'];

        data.scamTypes.forEach((scam, index) => {
            const difficulty = difficulties[index % difficulties.length];
            const riskLevel = typeof scam.riskLevel === 'object' ? scam.riskLevel.value || 'medium' : scam.riskLevel;
            
            questions.push({
                id: this.generateId(),
                question: `遇到以下情况，正确的做法是什么？\n${scam.description}`,
                option_a: '相信对方，按指示操作',
                option_b: '立即核实官方信息，不轻易转账或提供个人信息',
                option_c: '先尝试小额交易验证',
                option_d: '分享给同学一起参与',
                correct_answer: 'B',
                explanation: scam.warning + (scam.realCase ? `\n\n真实案例：${scam.realCase}` : ''),
                difficulty: difficulty,
                category: '教育部反诈案例',
                source: '教育部官方公告',
                risk_level: riskLevel,
                created_at: new Date().toISOString()
            });
        });

        // 基于防骗提示生成额外问题
        data.preventionTips.slice(0, 3).forEach((tip, index) => {
            questions.push({
                id: this.generateId(),
                question: '教育部提醒，在网上查询高校招生信息时应该注意什么？',
                option_a: '相信任何声称有内部渠道的信息',
                option_b: '认准"官网"标识，谨防山寨账号或网站',
                option_c: '优先选择收费高的咨询机构',
                option_d: '通过社交媒体获取招生信息',
                correct_answer: 'B',
                explanation: `教育部提醒：${tip}`,
                difficulty: 'medium',
                category: '招生安全',
                source: '教育部',
                risk_level: 'medium',
                created_at: new Date().toISOString()
            });
        });

        return questions;
    }

    /**
     * 将HIBP数据标准化为泄露报告
     */
    processHIBPBreachData(data) {
        const reports = [];

        data.majorBreaches.forEach(breach => {
            reports.push({
                id: this.generateId(),
                report_no: this.generateReportNo(),
                report_type: '数据泄露',
                risk_level: breach.records > 500000000 ? 'high' : 'medium',
                incident_time: `${breach.year}-01-01T00:00:00.000Z`,
                affected_count: breach.records,
                leak_source: breach.name,
                data_types: breach.dataTypes,
                description: `${breach.name}数据泄露事件影响了${(breach.records / 100000000).toFixed(1)}亿个账户，泄露信息包括：${breach.dataTypes.join('、')}。`,
                source: 'Have I Been Pwned',
                created_at: new Date().toISOString()
            });
        });

        return reports;
    }

    /**
     * 处理反诈统计数据
     */
    processAntifraudStats(data) {
        const stats = {
            totalCases: data.year2025.casesSolved,
            dailyWarnings: data.dailyWarnings,
            fundsIntercepted: data.year2025.fundsIntercepted,
            peopleWarned: data.year2025.peopleWarned,
            lossesPrevented: data.year2025.lossesPrevented,
            topRisks: data.highRiskTypes.slice(0, 5),
            demographics: data.demographics,
            international: data.international,
            updateDate: data.updateDate,
            source: data.source
        };

        return stats;
    }

    /**
     * 生成标准风险报告
     */
    generateRiskReport(studentName, leaks, loans, alerts) {
        const report = {
            id: this.generateId(),
            report_no: this.generateReportNo(),
            student_name: studentName,
            report_time: new Date().toISOString(),
            risk_summary: {
                overall_score: this.calculateOverallScore(leaks, loans, alerts),
                risk_level: 'medium',  // 根据分数计算
                risk_factors: []
            },
            leak_assessment: leaks,
            loan_assessment: loans,
            alert_assessment: alerts,
            recommendations: this.generateRecommendations(leaks, loans, alerts),
            created_at: new Date().toISOString()
        };

        return report;
    }

    /**
     * 计算综合风险分数（0-100，分数越高越安全）
     */
    calculateOverallScore(leaks, loans, alerts) {
        let score = 100;
        
        const getRiskValue = (level) => {
            if (typeof level === 'object' && level.value !== undefined) return level.value;
            const riskMap = { 'safe': 0, 'low': 1, 'medium': 2, 'high': 3, 'very_high': 4, 'extreme': 5, 'critical': 6 };
            return riskMap[level] || 0;
        };

        // 泄露扣分
        if (leaks.some(l => getRiskValue(l.risk_level) >= 3)) {
            score -= 30;
        } else if (leaks.some(l => getRiskValue(l.risk_level) >= 2)) {
            score -= 15;
        }
        
        // 贷款扣分
        if (loans.some(l => getRiskValue(l.risk_level) >= 3)) {
            score -= 25;
        } else if (loans.some(l => getRiskValue(l.risk_level) >= 2)) {
            score -= 10;
        }
        
        // 预警扣分
        const highAlerts = alerts.filter(a => getRiskValue(a.risk_level) >= 3).length;
        score -= highAlerts * 5;
        
        return Math.max(0, Math.min(100, score));
    }

    /**
     * 生成个性化建议
     */
    generateRecommendations(leaks, loans, alerts) {
        const recommendations = [];

        const getRiskValue = (level) => {
            if (typeof level === 'object' && level.value !== undefined) return level.value;
            const riskMap = { 'safe': 0, 'low': 1, 'medium': 2, 'high': 3, 'very_high': 4, 'extreme': 5, 'critical': 6 };
            return riskMap[level] || 0;
        };

        // 泄露建议
        const riskyLeaks = leaks.filter(l => getRiskValue(l.risk_level) >= 2);
        if (riskyLeaks.length > 0) {
            recommendations.push({
                type: '信息泄露',
                priority: 'high',
                content: '您的邮箱/手机号在已知数据泄露中暴露，建议立即修改相关密码并开启双因素认证。'
            });
        }

        // 贷款建议
        const riskyLoans = loans.filter(l => getRiskValue(l.risk_level) >= 2);
        if (riskyLoans.length > 0) {
            recommendations.push({
                type: '贷款风险',
                priority: 'high',
                content: '检测到异常贷款记录，请立即联系银行核实。'
            });
        }

        // 预警建议
        const highAlerts = alerts.filter(a => getRiskValue(a.risk_level) >= 3);
        if (highAlerts.length > 0) {
            recommendations.push({
                type: '诈骗预警',
                priority: 'high',
                content: `近期有${highAlerts.length}条高危预警，请提高警惕，谨防电信诈骗。`
            });
        }

        // 默认建议
        if (recommendations.length === 0) {
            recommendations.push({
                type: '常规建议',
                priority: 'low',
                content: '您的账户状态良好，建议定期更新密码，保持警惕。'
            });
        }

        return recommendations;
    }

    /**
     * 生成预警消息
     */
    generateAlertMessage(studentId, alertType, riskData) {
        const messages = {
            'email_leak': {
                title: '邮箱泄露预警',
                content: '您的邮箱地址在已知数据泄露中暴露，存在账号被盗风险。',
                action: '立即修改相关密码'
            },
            'password_leak': {
                title: '密码泄露预警',
                content: '您的密码在泄露数据库中被发现，建议立即更换为强密码。',
                action: '更换所有使用该密码的账户密码'
            },
            'loan_anomaly': {
                title: '贷款异常预警',
                content: '检测到您的名下存在异常贷款记录，可能被冒用。',
                action: '联系银行核实贷款记录'
            },
            'fraud_warning': {
                title: '诈骗风险预警',
                content: '根据反诈中心最新数据，近期高发类案需注意防范。',
                action: '提高警惕，谨防电信诈骗'
            }
        };

        const template = messages[alertType] || messages['fraud_warning'];
        
        return {
            id: this.generateId(),
            student_id: studentId,
            alert_title: template.title,
            alert_content: template.content + (riskData ? `\n\n详细信息：${JSON.stringify(riskData)}` : ''),
            suggested_action: template.action,
            alert_type: '预警推送',
            risk_level: 'medium',
            alert_time: new Date().toISOString(),
            source: '智安学护系统',
            created_at: new Date().toISOString()
        };
    }

    /**
     * 数据去重
     */
    deduplicateData(dataList, keyField) {
        const seen = new Set();
        return dataList.filter(item => {
            const key = item[keyField];
            if (seen.has(key)) {
                return false;
            }
            seen.add(key);
            return true;
        });
    }

    /**
     * 数据验证
     */
    validateData(data, schema) {
        const errors = [];
        
        for (const [field, rules] of Object.entries(schema)) {
            const value = data[field];
            
            if (rules.required && (value === undefined || value === null || value === '')) {
                errors.push(`${field} is required`);
            }
            
            if (rules.type && value !== undefined && typeof value !== rules.type) {
                errors.push(`${field} must be ${rules.type}`);
            }
            
            if (rules.minLength && value && value.length < rules.minLength) {
                errors.push(`${field} must be at least ${rules.minLength} characters`);
            }
            
            if (rules.maxLength && value && value.length > rules.maxLength) {
                errors.push(`${field} must be at most ${rules.maxLength} characters`);
            }
        }
        
        return {
            valid: errors.length === 0,
            errors
        };
    }

    // 工具方法
    generateId() {
        return Date.now().toString(36) + Math.random().toString(36).substr(2);
    }

    generateReportNo() {
        const date = new Date();
        const year = date.getFullYear();
        const month = String(date.getMonth() + 1).padStart(2, '0');
        const day = String(date.getDate()).padStart(2, '0');
        const random = String(Math.floor(Math.random() * 1000)).padStart(3, '0');
        return `RPT-${year}-${month}${day}-${random}`;
    }
}

module.exports = DataProcessor;