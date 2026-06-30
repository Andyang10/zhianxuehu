const https = require('https');

class DataFetcher {
    constructor() {
        this.sources = {
            NATIONAL_ANTIFRAUD: {
                name: '国家反诈中心',
                baseUrl: 'https://www.mps.gov.cn'
            },
            MOE_ANTIFRAUD: {
                name: '教育部反诈公告',
                baseUrl: 'https://www.moe.gov.cn'
            },
            HIBP_API: {
                name: 'Have I Been Pwned',
                baseUrl: 'https://haveibeenpwned.com/api/v3'
            }
        };
        this.cache = {};
        this.cacheExpiry = 3600000;
    }

    async fetchUrl(url, options = {}) {
        return new Promise((resolve, reject) => {
            const req = https.request(url, {
                ...options,
                headers: {
                    'User-Agent': 'zhianxuehu/1.0.0 (https://github.com/yangyuanyuan/zhianxuehu)',
                    ...options.headers
                }
            }, (res) => {
                let data = '';
                res.on('data', chunk => data += chunk);
                res.on('end', () => {
                    if (res.statusCode === 200) {
                        try {
                            resolve(JSON.parse(data));
                        } catch (e) {
                            resolve(data);
                        }
                    } else if (res.statusCode === 404) {
                        resolve(null);
                    } else {
                        reject(new Error(`HTTP ${res.statusCode}`));
                    }
                });
            });
            req.on('error', reject);
            req.end();
        });
    }

    async getNationalAntifraudStats() {
        const cacheKey = 'national_antifraud';
        if (this.cache[cacheKey] && Date.now() - this.cache[cacheKey].timestamp < this.cacheExpiry) {
            return this.cache[cacheKey].data;
        }

        try {
            const data = {
                dailyWarnings: 2000000,
                highRiskTypes: [
                    { type: '刷单返利', count: 2580000, trend: 'up' },
                    { type: '虚假购物服务', count: 1920000, trend: 'stable' },
                    { type: '虚假网络投资理财', count: 1850000, trend: 'up' },
                    { type: '冒充电商物流客服', count: 1540000, trend: 'down' },
                    { type: '贷款征信', count: 1380000, trend: 'stable' },
                    { type: '网络游戏虚假交易', count: 1150000, trend: 'up' },
                    { type: '网络婚恋交友', count: 920000, trend: 'stable' },
                    { type: '冒充公检法', count: 840000, trend: 'down' },
                    { type: '冒充领导熟人', count: 690000, trend: 'down' },
                    { type: '机票退改签', count: 630000, trend: 'stable' }
                ],
                year2025: {
                    casesSolved: 258000,
                    phonesBlocked: 3600000000,
                    smsBlocked: 3300000000,
                    domainsBlocked: 8162000,
                    fundsIntercepted: 2170700000000,
                    peopleWarned: 6747000,
                    lossesPrevented: 35000000000000
                },
                international: {
                    suspectsRepatriated: 58000,
                    gamblingFraudSites: 127,
                    majorArrests: ['陈志', '佘智江', '李雄']
                },
                demographics: {
                    ageRange: { min: 10, max: 95, peak: '18-60岁' },
                    gender: { male: { victims: '略多', losses: '略少' }, female: { victims: '略少', losses: '略多' } },
                    youthRisks: ['网络游戏产品虚假交易', '冒充公检法诈骗'],
                    elderlyRisks: ['冒充电商物流客服诈骗']
                },
                updateDate: '2026-06-10',
                source: '公安部刑侦局、新华社',
                isRealApi: false,
                apiNote: '国家反诈中心无公开API，数据来源于官方新闻发布会通报'
            };
            this.cache[cacheKey] = { data, timestamp: Date.now() };
            return data;
        } catch (error) {
            console.error('获取国家反诈数据失败:', error.message);
            return this.getFallbackNationalData();
        }
    }

    getFallbackNationalData() {
        return {
            dailyWarnings: 2000000,
            highRiskTypes: [
                { type: '刷单返利', count: 2580000, trend: 'up' },
                { type: '虚假网络投资理财', count: 1850000, trend: 'up' },
                { type: '冒充电商物流客服', count: 1540000, trend: 'down' },
                { type: '贷款征信', count: 1380000, trend: 'stable' },
                { type: '网络游戏虚假交易', count: 1150000, trend: 'up' },
                { type: '网络婚恋交友', count: 920000, trend: 'stable' },
                { type: '冒充公检法', count: 840000, trend: 'down' },
                { type: '冒充领导熟人', count: 690000, trend: 'down' },
                { type: '机票退改签', count: 630000, trend: 'stable' },
                { type: '虚假购物服务', count: 1920000, trend: 'stable' }
            ],
            year2025: {
                casesSolved: 258000,
                phonesBlocked: 3600000000,
                smsBlocked: 3300000000,
                domainsBlocked: 8162000,
                fundsIntercepted: 2170700000000,
                peopleWarned: 6747000,
                lossesPrevented: 35000000000000
            },
            updateDate: '2026-06-10',
            source: '公安部刑侦局（数据缓存）',
            isRealApi: false
        };
    }

    async getMoeAntifraudCases() {
        const cacheKey = 'moe_antifraud';
        if (this.cache[cacheKey] && Date.now() - this.cache[cacheKey].timestamp < this.cacheExpiry) {
            return this.cache[cacheKey].data;
        }

        try {
            const data = {
                scamTypes: [
                    {
                        type: '内部指标、低分上名校',
                        description: '声称有内部招生老师、教育局工作人员、高校领导家属，有预留机动名额、补录计划',
                        realCase: '上海嘉定公安打掉大型招生诈骗团伙，22名家长受骗，涉案金额900多万元',
                        warning: '百分百虚假，高校录取全程由省级教育考试院统一计算机投档',
                        riskLevel: 'high'
                    },
                    {
                        type: '天价志愿填报机构',
                        description: '收费几千到上万元，声称掌握考试院内部大数据、独家填报算法',
                        warning: '国家《职业资格目录》内没有"高考志愿规划师"职业，不存在所谓内部大数据',
                        realCase: '北京考生家长花2万元请"专家"推荐学校，孩子一个都没录取上',
                        riskLevel: 'medium'
                    },
                    {
                        type: '提前查分、改分',
                        description: '发送短信声称可以提前查分、黑客改分、内部操作',
                        warning: '高考数据经多重加密备份，系统防入侵等级高，"黑客改分"为骗局',
                        realCase: '李同学点击查分链接，银行卡被盗刷2万余元',
                        riskLevel: 'high'
                    },
                    {
                        type: '发放助学金先交手续费',
                        description: '自称"教育部工作人员"，称孩子获得助学金但需要先交"手续费"',
                        warning: '所有奖助学金发放均通过官方渠道，不会要求提前缴纳费用',
                        realCase: '考生家长接到电话称获得5000元助学金，要求先交500元手续费',
                        riskLevel: 'medium'
                    },
                    {
                        type: '高考作弊短信',
                        description: '发送短信称在高考过程中发现作弊行为，要求支付"罚款"',
                        warning: '考后切勿轻信任何涉高考作弊的短信，不点链接、不下载APP',
                        riskLevel: 'high'
                    }
                ],
                preventionTips: [
                    '认准"官网"标识，谨防山寨账号或网站',
                    '高校招生不存在"内部指标"等说法',
                    '妥善保管身份证号、考生号等个人信息',
                    '志愿填报系统使用官方免费服务',
                    '通过省教育考试院官网、阳光高考平台查询录取信息'
                ],
                updateDate: '2026-06-27',
                source: '教育部、新华社',
                isRealApi: false,
                apiNote: '教育部无公开API，数据来源于官方预警公告'
            };
            this.cache[cacheKey] = { data, timestamp: Date.now() };
            return data;
        } catch (error) {
            console.error('获取教育部数据失败:', error.message);
            return this.getFallbackMoeData();
        }
    }

    getFallbackMoeData() {
        return {
            scamTypes: [
                { type: '内部指标招生诈骗', description: '声称有内部名额', warning: '高校录取全程公开透明', riskLevel: 'high' },
                { type: '志愿填报诈骗', description: '高价志愿填报指导', warning: '不存在内部大数据', riskLevel: 'medium' },
                { type: '助学金诈骗', description: '要求先交手续费', warning: '官方不收取任何费用', riskLevel: 'high' },
                { type: '提前查分诈骗', description: '声称可提前查分改分', warning: '高考数据加密保护', riskLevel: 'high' }
            ],
            preventionTips: ['认准官方渠道', '保护个人信息', '不轻信陌生电话'],
            updateDate: '2026-06',
            source: '教育部（数据缓存）',
            isRealApi: false
        };
    }

    async getHIBPBreachStats() {
        const cacheKey = 'hibp_breaches';
        if (this.cache[cacheKey] && Date.now() - this.cache[cacheKey].timestamp < this.cacheExpiry) {
            console.log('使用HIBP数据缓存');
            return this.cache[cacheKey].data;
        }

        try {
            console.log('正在调用HIBP真实API获取数据...');
            const breaches = await this.fetchUrl('https://haveibeenpwned.com/api/v3/breaches');
            
            if (!breaches || !Array.isArray(breaches)) {
                throw new Error('HIBP API返回无效数据');
            }

            const sortedBreaches = breaches
                .filter(b => b.PwnCount && b.IsVerified)
                .sort((a, b) => b.PwnCount - a.PwnCount)
                .slice(0, 10);

            const totalAccounts = breaches.reduce((sum, b) => sum + (b.PwnCount || 0), 0);

            const data = {
                totalBreachedAccounts: totalAccounts,
                totalBreaches: breaches.length,
                verifiedBreaches: breaches.filter(b => b.IsVerified).length,
                majorBreaches: sortedBreaches.map(b => ({
                    name: b.Name,
                    year: b.BreachDate ? b.BreachDate.substring(0, 4) : '未知',
                    records: b.PwnCount,
                    dataTypes: b.DataClasses || [],
                    verified: b.IsVerified,
                    description: b.Description || ''
                })),
                updateDate: new Date().toISOString().split('T')[0],
                source: 'Have I Been Pwned API',
                isRealApi: true,
                apiEndpoint: 'https://haveibeenpwned.com/api/v3/breaches'
            };

            this.cache[cacheKey] = { data, timestamp: Date.now() };
            console.log(`✓ HIBP API调用成功，获取到${breaches.length}个数据泄露事件`);
            return data;

        } catch (error) {
            console.error('HIBP API调用失败，使用备用数据:', error.message);
            return this.getFallbackHIBPData();
        }
    }

    getFallbackHIBPData() {
        return {
            totalBreachedAccounts: 12000000000,
            totalBreaches: 500,
            verifiedBreaches: 450,
            majorBreaches: [
                { name: 'Collection #1-5', year: 2019, records: 2200000000, dataTypes: ['Emails', 'Passwords'], verified: true },
                { name: 'LinkedIn', year: '2012/2021', records: 700000000, dataTypes: ['Emails', 'Passwords', 'Profile Data'], verified: true },
                { name: 'Facebook', year: 2019, records: 533000000, dataTypes: ['Phone Numbers', 'Names', 'Emails'], verified: true },
                { name: 'MySpace', year: 2016, records: 360000000, dataTypes: ['Emails', 'Passwords', 'Usernames'], verified: true },
                { name: 'Adobe', year: 2013, records: 153000000, dataTypes: ['Emails', 'Encrypted Passwords'], verified: true }
            ],
            updateDate: '2026-06',
            source: 'Have I Been Pwned（数据缓存）',
            isRealApi: false
        };
    }

    async checkEmailBreach(email) {
        try {
            console.log(`正在调用HIBP API检查邮箱: ${email}`);
            const result = await this.fetchUrl(
                `https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(email)}`,
                { headers: { 'hibp-api-key': process.env.HIBP_API_KEY || '' } }
            );

            if (!result) {
                return { breached: false, message: '未在已知数据泄露中发现该邮箱', isRealApi: true };
            }

            if (Array.isArray(result) && result.length > 0) {
                const breaches = result.slice(0, 3).map(b => ({
                    breachName: b.Name,
                    breachDate: b.BreachDate,
                    pwnCount: b.PwnCount,
                    dataClasses: b.DataClasses || [],
                    verified: b.IsVerified
                }));

                return {
                    breached: true,
                    breaches,
                    totalBreaches: result.length,
                    isRealApi: true,
                    riskLevel: result.length >= 3 ? 'high' : 'medium'
                };
            }

            return { breached: false, message: '未在已知数据泄露中发现该邮箱', isRealApi: true };

        } catch (error) {
            console.log('HIBP邮箱查询失败，使用模拟:', error.message);
            return this.getFallbackEmailCheck(email);
        }
    }

    getFallbackEmailCheck(email) {
        const domain = email.split('@')[1];
        const highRiskDomains = ['qq.com', '163.com', 'sina.com', 'yahoo.com', 'hotmail.com'];
        const mediumRiskDomains = ['gmail.com', 'outlook.com', '126.com'];

        if (highRiskDomains.includes(domain) && Math.random() > 0.4) {
            return {
                breached: true,
                breaches: [{ breachName: '历史数据泄露', breachDate: '2020-01-01', pwnCount: 500000000, dataClasses: ['Email', 'Password'] }],
                totalBreaches: 1,
                isRealApi: false,
                riskLevel: 'high',
                apiNote: 'HIBP API调用受限，此结果为模拟'
            };
        }

        if (mediumRiskDomains.includes(domain) && Math.random() > 0.6) {
            return {
                breached: true,
                breaches: [{ breachName: '部分数据泄露', breachDate: '2021-06-01', pwnCount: 100000000, dataClasses: ['Email'] }],
                totalBreaches: 1,
                isRealApi: false,
                riskLevel: 'medium',
                apiNote: 'HIBP API调用受限，此结果为模拟'
            };
        }

        return {
            breached: false,
            message: '未在已知数据泄露中发现该邮箱',
            isRealApi: false,
            apiNote: 'HIBP API调用受限，此结果为模拟'
        };
    }

    async checkPasswordLeak(password) {
        const crypto = require('crypto');
        const hash = crypto.createHash('sha1').update(password).digest('hex').toUpperCase();
        const prefix = hash.substring(0, 5);
        const suffix = hash.substring(5);

        try {
            console.log(`正在调用HIBP Password API检查密码（前缀: ${prefix}）`);
            const response = await this.fetchUrl(`https://api.pwnedpasswords.com/range/${prefix}`);

            if (!response || typeof response !== 'string') {
                throw new Error('HIBP Password API返回无效数据');
            }

            const lines = response.split('\n');
            const found = lines.find(line => line.startsWith(suffix));

            if (found) {
                const count = parseInt(found.split(':')[1].trim());
                return {
                    leaked: true,
                    leakCount: count,
                    riskLevel: this.getPasswordRiskLevel(count),
                    recommendation: this.getPasswordRecommendation(count),
                    isRealApi: true
                };
            }

            return {
                leaked: false,
                message: '该密码未在已知泄露数据库中发现',
                isRealApi: true
            };

        } catch (error) {
            console.log('HIBP密码查询失败，使用模拟:', error.message);
            return this.getFallbackPasswordCheck(password);
        }
    }

    getFallbackPasswordCheck(password) {
        const weakPatterns = ['123456', 'password', '12345678', 'qwerty', 'abc123', '1234567', 'password1', 'admin', '123123', 'welcome'];
        
        if (weakPatterns.includes(password.toLowerCase())) {
            const count = Math.floor(Math.random() * 10000000) + 1000000;
            return {
                leaked: true,
                leakCount: count,
                riskLevel: 'critical',
                recommendation: '这是常见密码，立即更换',
                isRealApi: false,
                apiNote: 'HIBP API调用受限，此结果为模拟'
            };
        }

        if (password.length < 8) {
            const count = Math.floor(Math.random() * 1000000) + 10000;
            return {
                leaked: Math.random() > 0.7,
                leakCount: count,
                riskLevel: 'high',
                recommendation: '密码太短，建议使用12位以上复杂密码',
                isRealApi: false,
                apiNote: 'HIBP API调用受限，此结果为模拟'
            };
        }

        return {
            leaked: false,
            message: '该密码未在已知泄露数据库中发现',
            isRealApi: false,
            apiNote: 'HIBP API调用受限，此结果为模拟'
        };
    }

    getPasswordRiskLevel(count) {
        if (count === 0) return 'safe';
        if (count < 100) return 'high';
        if (count < 10000) return 'very_high';
        if (count < 1000000) return 'extreme';
        return 'critical';
    }

    getPasswordRecommendation(count) {
        if (count === 0) return '密码安全，但建议定期更换';
        if (count < 100) return '立即更改所有使用该密码的账户';
        if (count < 10000) return '该密码被频繁使用，立即更改并启用双因素认证';
        if (count < 1000000) return '这是常见密码，立即更换为复杂密码并启用双因素认证';
        return '这是最常见密码之一，立即更换，不要在任何地方使用';
    }

    async getAllStats() {
        const [nationalStats, moeCases, hibpStats] = await Promise.all([
            this.getNationalAntifraudStats(),
            this.getMoeAntifraudCases(),
            this.getHIBPBreachStats()
        ]);

        return {
            national: nationalStats,
            moe: moeCases,
            hibp: hibpStats,
            lastUpdate: new Date().toISOString()
        };
    }

    clearCache() {
        this.cache = {};
    }
}

module.exports = DataFetcher;