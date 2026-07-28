**CHAPTER I**

**THE PROBLEM AND ITS BACKGROUND**

INTRODUCTION

The internet has significantly transformed how people communicate, learn, and work, making it an essential part of everyday life. Originally designed as a platform for communication and information exchange, it has evolved into a complex digital ecosystem that supports remote work, online education, e-commerce, entertainment, and collaboration. The widespread adoption of smartphones, improvements in broadband connectivity, and the emergence of algorithm-driven content recommendation systems have made digital resources more accessible to people worldwide. These developments have increased productivity across many sectors and have reshaped the way individuals interact with information and technology.

Despite these benefits, the rapid expansion of digital connectivity has also introduced new challenges. Continuous exposure to online content can lead to excessive digital media consumption, which may affect concentration, time management, and overall digital well-being. Studies indicate that many digital platforms utilize psychological engagement strategies such as variable reward systems and algorithmic content recommendations that encourage repeated checking and scrolling behaviors \[6\]. Over time, this pattern of usage can lead to distractions, disrupted routines, and reduced productivity.

The issue is particularly noticeable in the Philippines, where internet usage continues to grow rapidly. In 2023, internet penetration in the Philippines exceeded 73% of the population, while average daily screen time reached 8 hours and 52 minutes, ranking the country third among those with the highest internet usage worldwide \[1\], \[9\]. While widespread internet access has contributed to improved communication, education, and economic opportunities, it has also increased the risk of digital overconsumption and its related negative effects \[15\].

Young people, particularly students and young professionals, are among the most affected by these trends. Many spend long hours on social media platforms, short-form video applications, and algorithm-driven content feeds \[16\]. Recent clinical findings suggest that digital addiction significantly impairs cognitive performance \[5\]. Furthermore, longitudinal studies specifically examining university students have identified a trend of 'brain rot,' characterized by a measurable decline in sustained attention spans and a diminished capacity for deep analytical thinking \[7\]. Additionally, research suggests that frequent engagement with short-form video platforms may overstimulate neural pathways, elevating stress levels and undermining self-regulatory mechanisms during digital consumption \[3\].

Traditional network management systems, such as DNS-based filtering tools, were originally designed for earlier internet environments and often struggle to address modern digital behavior. These systems typically rely on domain-level blocking, which may incorrectly block legitimate websites or allow users to bypass restrictions through VPN services or alternative DNS providers \[10\], \[11\]. As a result, organizations and households often face difficulties implementing effective digital control mechanisms without restricting access to important online resources \[2\].

To address these challenges, this study proposes the development of VIGILANT: A Virtual Inspection Gateway with Intelligent Logging and Access Network Traffic Control. The system uses Natural Language Processing (NLP) and transparent proxy interception to analyze network traffic and understand the context of online content. The system is designed to identify browsing behaviors associated with unhealthy digital habits such as doomscrolling, which refers to repetitive and compulsive engagement with negative or addictive online content.

Unlike traditional filtering approaches that rely on strict blocking rules, the proposed system focuses on contextual analysis and behavioral monitoring. By doing so, it aims to encourage healthier internet usage while still allowing access to essential digital resources.

Following the COVID-19 pandemic, remote work and online learning became more common in the Philippines. As a result, the boundaries between work, academic, and personal online activities have become increasingly blurred \[17\]. This situation highlights the need for intelligent network management systems that can support productivity while encouraging responsible digital behavior and protecting user privacy. Through the development of VIGILANT., this study aims to contribute to the creation of adaptive network systems that support healthier digital environments in households, educational institutions, and small office settings.

Background of the Study

Since its early development, the internet has undergone several significant transformations. Initially developed as a decentralized communication network for military and academic purposes, the internet expanded globally during the 1990s when it became commercially available to the public. While improvements in broadband infrastructure and wireless communication technologies have enabled individuals to remain connected almost continuously \[12\], this 'always-on' environment has exacerbated the challenges of digital over-consumption. Consequently, as internet penetration and screen time reached record highs in the Philippines \[1\], \[9\], the resulting cognitive fatigue \[5\] has prompted a need for more effective, yet less intrusive digital management systems.

Although these technological advancements greatly improved access to information and global communication, they also contributed to increased digital distractions and information overload \[13\]. Current global statistics indicate that individuals spend an average of approximately 6 hours and 40 minutes online each day. In the Philippines, internet users spend significantly more time online, averaging 8 hours and 52 minutes daily \[1\], \[9\]. This represents a significant increase compared to the pre-smartphone era, when average screen time was typically reported at only two to three hours per day.

A substantial portion of this time is spent on mobile devices, particularly through social media platforms and video streaming services \[9\]. Short-form video platforms such as TikTok, Instagram Reels, and YouTube Shorts rely heavily on algorithm-based recommendation systems that continuously present users with personalized content \[4\]. While these algorithms effectively maximize retention, they also facilitate repetitive consumption loops that contribute to cognitive fatigue and diminished attentional control \[3\].

Another behavior associated with excessive internet use is doomscrolling, which refers to the continuous browsing of negative or emotionally intense content for extended periods \[14\]. Studies suggest that individuals who frequently engage in doomscrolling may experience mental exhaustion, sleep disturbances, increased anxiety, and reduced productivity.

The growing dependence on internet connectivity has also affected modern workplace environments. The rise of remote work and hybrid working arrangements has made internet access essential for many professional tasks. However, constant connectivity can also create opportunities for digital distraction. Employees working remotely may frequently switch between professional tasks and personal online activities, such as browsing social media or watching online videos \[17\]. Research shows that excessive digital engagement can contribute to procrastination, reduced work efficiency, and increased work-related errors.

Furthermore, traditional network control systems remain limited in addressing modern digital behaviors. Most DNS-based filtering solutions rely on domain-level blacklisting, a 'blunt' method that often lacks the granularity to analyze specific web content \[10\]. This lack of context can lead to the accidental blocking of legitimate resources, while technically proficient users, particularly among the youth, frequently bypass these restrictions using VPNs or alternative DNS providers \[11\]. This approach may incorrectly block legitimate educational resources or allow users to bypass restrictions through VPN services. Additionally, some cloud-based filtering systems raise privacy concerns because user browsing data must be transmitted to third-party servers for analysis \[8\].

Within the Philippine context, these issues can significantly affect both productivity and mental well-being. Recent studies on digital engagement in the country have highlighted a direct correlation between extensive device use and the manifestation of digital stress, which contributes to cognitive fatigue and burnout among users \[2\]. Similarly, research involving university students has identified high levels of social media fatigue, suggesting that excessive digital engagement can negatively affect academic performance and mental health.

Emerging technologies such as edge computing offer potential solutions to these challenges. Edge computing allows data processing to occur locally within the network environment instead of relying entirely on remote cloud infrastructure. By analyzing traffic directly on local devices, systems can reduce latency while improving privacy and responsiveness \[18\].

When combined with techniques, network monitoring systems can analyze the meaning and context of web content rather than relying solely on domain-level filtering. This approach allows systems to differentiate between educational, productive, and potentially harmful content, enabling a more intelligent and adaptive method of internet management.

By integrating contextual analysis, behavioral monitoring, and local network processing, the proposed VIGILANT system aims to provide a more balanced approach to managing internet usage. The system seeks to address the limitations of traditional filtering technologies while promoting healthier digital habits and maintaining network performance and user privacy

OBJECTIVES OF THE STUDY

Research objectives describe what the study intends to achieve and guide the direction of the research. They help define the scope of the project and ensure that the study remains aligned with the research problem.

General Objective

To design, develop, and evaluate VIGILANT: A Virtual Inspection Gateway with Intelligent Logging and Access Network Traffic Control, a specialized network gateway that utilizes Transparent Proxy Interception and Natural Language Processing (NLP) to provide context-aware content filtering and mitigate doomscrolling behavior while maintaining high network performance.

Specific Objectives

1.  To establish a Transparent Interception Gateway, implemented via mitmproxy, that intercepts and routes client TCP/UDP traffic without requiring manual proxy configuration (IP/Port) on the guest device, thereby achieving transparency as defined by the ability to intercept network traffic seamlessly; success shall be measured by attaining a successful interception rate of no less than 95% of all HTTP and HTTPS requests captured during controlled testing.
2.  To implement an NLP-based content categorization module using spaCy that utilizes Named Entity Recognition (NER) to classify intercepted web content into four predefined categories (Educational, Productive, Distracting, and Harmful) using parameterized input features such as keyword frequencies and named entity counts; and to quantitatively validate its categorization accuracy by achieving a minimum threshold of 85% accuracy (F1-score) across a labeled baseline test dataset, measured via a per-category classification rate and a confusion matrix analysis.
3.  To develop a behavioral throttling module that monitors request velocity, defined as the number of HTTP/HTTPS requests per unit time per connected device, and detects doomscrolling by comparing a device’s rolling request rate against computed per-session averages; doomscrolling shall be flagged when request velocity exceeds a configurable threshold value set at a percentage above the session average (e.g., 150% of baseline), at which point dynamic bandwidth throttling is applied to the offending device to incentivize healthier browsing behavior.
4.  To evaluate the system’s impact on network performance by measuring throughput (Mbps) and latency (ms) under a hardware environment provisioned with 8 GB of RAM, targeting a throughput efficiency of no less than 90% relative to an unfiltered baseline network operating under equivalent conditions and load.
5.  To validate the reliability and stability of the VIGILANT system through stress testing conducted with 30 concurrent connected devices, ensuring that the gateway maintains uninterrupted operation, consistent interception performance, and stable throughput levels throughout the duration of each test session without system failure or critical service degradation.

These objectives guide the methodology by adopting a Quantitative Experimental Research design to evaluate the technical efficacy and performance of the VIGILANT gateway. The research focuses on empirical data collection through controlled network simulations and system stress tests,

SIGNIFICANCE OF THE STUDY

The significance of the study highlights the potential contributions of the proposed system to various stakeholders, including academic institutions, information technology practitioners, researchers, and end users. The development of VIGILANT: A Virtual Inspection Gateway with Intelligent Logging and Access Network Traffic Control aims to address issues related to excessive digital media consumption and digital distractions by providing an intelligent and context-aware network monitoring solution.

**Batangas State University The National Engineering University** The research contributes to the university’s mission of promoting advanced technological solutions and research-driven innovation. The project also reflects the university’s commitment to producing competent graduates capable of addressing real-world technological challenges.

**College of Informatics and Computing Sciences (CICS)** The study contributes to the advancement of knowledge in areas such as network security, intelligent systems, and data analytics. The integration of multiple technologies, including transparent proxy interception, Natural Language Processing, and behavioral traffic monitoring, demonstrates practical applications of concepts taught within the college. The system may also serve as a reference project for future students pursuing research in cybersecurity, artificial intelligence, and network systems.

**End Users (Students, Households, and Small Offices)** The proposed system may benefit end users by promoting healthier internet usage habits and reducing exposure to distracting or harmful online content. By implementing context-aware filtering and behavioral monitoring, the system can help users maintain focus and improve productivity while still allowing access to essential online resources. This can be particularly beneficial for students, remote workers, and small office environments where excessive digital distractions may negatively affect performance and efficiency.

**Future Researchers** This study may serve as a valuable reference for future researchers interested in intelligent network monitoring, AI-based content filtering, and digital well-being technologies. Future studies may expand upon the system by incorporating more advanced machine learning models, larger network environments, or additional behavioral analysis techniques to further enhance the effectiveness of digital distraction management systems.

**Researchers** The study provides an opportunity to apply theoretical concepts learned in their academic program to the development of a functional technological solution. Through the design and implementation of the VIGILANT system, the researchers gain practical experience in network configuration, system development, and data analysis. Additionally, the research enhances their technical competencies and problem-solving skills while contributing to discussions related to digital well-being and responsible internet usage.

SCOPE AND LIMITATION OF THE STUDY

Scope of the Study

This study focuses on the design, development, and technical evaluation of VIGILANT: A Virtual Inspection Gateway with Intelligent Logging and Access Network Traffic Control, a context-aware network gateway that will be deployed on an edge device. The system operates as a transparent access point using *hostapd*, allowing it to automatically route and monitor internet traffic from connected client devices without requiring manual proxy configuration. The implementation of the system is conducted within a controlled test environment consisting of up to five concurrent client devices connected to the network.

The system is developed using a localized software environment based on Ubuntu Server 24.04. The core technologies utilized in the system include Python 3.x for system development, mitmproxy for Secure Socket Layer (SSL) interception, and spaCy (en\_core\_web\_sm) for Natural Language Processing. Within the scope of the study, the system performs contextual filtering through real-time Named Entity Recognition (NER) to analyze and categorize web content. It also implements behavioral throttling, which applies logic-based bandwidth limitations when the system detects rapid request patterns associated with excessive browsing behavior on selected social media platforms.

In addition, the study includes performance benchmarking to evaluate the impact of the system on network performance. This evaluation involves measuring key metrics such as throughput, expressed in megabits per second (Mbps), and latency, measured in milliseconds (ms). The system also provides local administrative control through a responsive Flask-based web dashboard, which enables administrators to monitor network activity and manage filtering rules in real time.

The research follows a quantitative experimental research design, where the technical performance and efficiency of the system are evaluated through controlled network testing and data analysis.

Limitation of the Study

Despite the capabilities of the proposed system, several limitations are identified to maintain the feasibility of the study within the academic timeframe. The system supports traffic interception only for HTTP, HTTPS, and WebSocket protocols, which means that other specialized network protocols are not included in the scope of this research.

Although the system can intercept browser-based HTTPS traffic through the use of a locally installed Root Certificate Authority (CA), it cannot decrypt traffic from certain mobile applications that implement SSL pinning, such as the Facebook and Instagram mobile applications. In such cases, the system relies on Server Name Indication (SNI) metadata to identify the domain being accessed and apply behavioral throttling mechanisms.

Furthermore, the system is limited by the processing capabilities of the hardware platform to be utilized. As a result, the system is designed primarily for low-density environments, such as households or small office settings, and is not intended for large-scale enterprise deployment.

Lastly, the study focuses solely on the technical evaluation of the system, including measurements of network throughput and latency. Qualitative evaluation such as user experience surveys or behavioral assessments, are not included in this study.

DEFINITION OF TERMS

This section presents the definitions of key terms and technical concepts used throughout the study. The purpose of defining these terms is to provide readers with a clear understanding of specialized words, acronyms, and system-related terminology that may not be commonly known. The definitions are presented to establish a common interpretation of important concepts related to the development and implementation of the proposed system. For clarity and consistency, the terms are arranged alphabetically and are defined according to how they are used within the context of this study.

**Bandwidth** It refers to the maximum amount of data that can be transmitted over a network connection within a given time period. In this study, bandwidth is managed by the system to regulate user browsing behavior through behavioral throttling.

**Behavioral Throttling** It refers to the dynamic limitation of network speed based on detected user browsing patterns. In this study, the system applies bandwidth throttling when browsing activity indicates behaviors associated with excessive scrolling or prolonged consumption of distracting online content.

**Brain Rot** Informal term for cognitive degradation from excessive screen time, linked to attention deficits \[22\]. In this study, brain rot refers to the potential cognitive effects associated with prolonged exposure to distracting or low-value online content, which the proposed system aims to mitigate through intelligent filtering and monitoring.

**Broadband Connectivity** It refers to high-speed internet access that allows large amounts of data to be transmitted quickly over communication networks. In this study, broadband connectivity represents the modern infrastructure that enables continuous online access.

**Client Device** It refers to any user device connected to a network that requests services or data from a server. In this study, client devices include computers, smartphones, or tablets connected to the VIGILANT gateway.

**Cognitive Fatigue** It refers to mental exhaustion that occurs after prolonged periods of intense concentration or information processing. In this study, cognitive fatigue may result from excessive exposure to fast-paced digital content.

**Content Categorization** It refers to the process of organizing digital information into predefined categories based on its topic or context. In this study, content categorization is performed using Named Entity Recognition to classify web content.

**Contextual Filtering** It refers to the process of analyzing the meaning and context of online content in order to determine whether it should be restricted or allowed. In this study, contextual filtering is performed by the V.I.G.I.L.A.N.T. system using Natural Language Processing techniques to evaluate web content before allowing access.

**DNS-Based Filtering** It refers to a network filtering technique that blocks or allows access to websites based on their domain names. In this study, DNS-based filtering is discussed as a traditional approach that lacks contextual understanding of web content.

**Domain** It refers to the human-readable address used to access websites on the internet, such as example.com. In this study, domains are analyzed to identify the websites accessed by users.

**Doomscrolling** It refers to the compulsive and continuous consumption of negative, distressing, or addictive online content, particularly on social media platforms, which may lead to decreased productivity and increased stress levels \[14\]. In this study, doomscrolling refers to the prolonged browsing of distracting or harmful online content that the proposed system detects and filters through network monitoring and content analysis mechanisms.

**Edge Computing** Processing data near its source on local devices to minimize latency and enhance privacy \[18\]. In this study, edge computing refers to the use of a local device to process and filter network traffic in real time before it reaches external servers.

**HTTP (Hypertext Transfer Protocol)** It refers to the standard communication protocol used for transferring web pages and other resources between a web browser and a server over the internet.

**HTTPS (Hypertext Transfer Protocol Secure)** It refers to the secure version of HTTP that encrypts data transmitted between a web browser and a server using Secure Socket Layer or Transport Layer Security protocols.

**Latency** It refers to the delay between sending a request over a network and receiving the corresponding response. In this study, latency is measured to assess how the proposed system affects network responsiveness.

**Named Entity Recognition (NER)** Natural Language Processing technique used to identify and categorize important elements in text such as names, organizations, locations, or topics. In this study, NER is used to classify web content to support the system’s contextual filtering mechanism.

**Natural Language Processing (NLP)** AI techniques for analyzing text semantics, used here for context-aware filtering \[18\]. In this study, NLP is used as a filtering mechanism that analyzes the semantic meaning of online text content to identify and block potentially harmful or distracting information.

**Network Gateway** It refers to a hardware or software system that acts as an entry and exit point between different networks, allowing communication and traffic management.

**Network Traffic** It refers to the data transmitted between devices within a computer network. In this study, network traffic refers to the internet requests and responses generated by client devices that are monitored and analyzed by the V.I.G.I.L.A.N.T. system.

**Request Velocity** It refers to the rate at which a user sends network requests within a given period of time. In this study, request velocity is monitored to detect browsing patterns associated with excessive scrolling behavior.

**Root Certificate Authority (Root CA)** It refers to a trusted digital certificate installed on a device that allows a system to intercept and decrypt encrypted network traffic for analysis.

**Server Name Indication (SNI)** A feature of the TLS protocol that allows a client device to specify the hostname it wants to connect to during the encryption process. In this study, SNI information is used to identify domains when encrypted traffic cannot be fully decrypted.

**SSL Pinning** A security technique used by some mobile applications to prevent interception of encrypted traffic. In this study, SSL pinning limits the ability of the system to decrypt certain application traffic such as Facebook or Instagram mobile apps.

**TCP (Transmission Control Protocol)** It refers to a core internet protocol that ensures reliable and ordered delivery of data between devices on a network.

**Throughput** It refers to the amount of data successfully transmitted through a network within a specific period of time, usually measured in megabits per second (Mbps). In this study, throughput is used as a metric to evaluate the system’s network performance.

**Transparent Proxy** A network intermediary that intercepts traffic without client configuration, enabling seamless inspection \[0\]. In this study, the transparent proxy functions as the system component that automatically intercepts users’ internet requests to analyze and filter web content without requiring manual setup on the user’s device.

**UDP (User Datagram Protocol)** It refers to a communication protocol used for transmitting data quickly across networks without requiring guaranteed delivery.

**VPN (Virtual Private Network)** It refers to a network service that encrypts internet traffic and routes it through remote servers to protect user privacy and bypass network restrictions.

**Web-Based Dashboard** A graphical interface that allows administrators to monitor system activity and manage configurations through a web browser. In this study, the dashboard is used to visualize network activity and control filtering rules.

**WebSocket** It refers to a communication protocol that allows continuous two-way data exchange between a client and server over a single network connection.

REFERENCES

\[1\] N. Kumar, “Average Screen Time Statistics 2026 \[By Age & Country\],” DemandSage, Mar. 09, 2026. \[Online\]. Available: https://www.demandsage.com/screen-time-statistics/ (accessed Mar. 12, 2026).

\[2\] L. R. Giray, “A survey on digital device engagement, digital stress, and coping strategies among college students in the Philippines,” Journal of Youth Studies, vol. 27, no. 6, pp. 1–18, 2024. \[Online\]. Available: https://www.tandfonline.com/doi/full/10.1080/02673843.2024.2371413 (accessed Mar. 12, 2026).

\[3\] F. Baumann et al., “Dynamics of Algorithmic Content Amplification on TikTok,” arXiv preprint arXiv:2311.11970, 2024. \[Online\]. Available: https://arxiv.org/abs/2311.11970

\[4\] “Short-form video content shows distinct patterns of engagement,” Adv. Int. J. Bus. Entrep. SMEs (AIJBES), vol. 7, no. 25, pp. 470–479, 2025. \[Online\]. Available: https://gaexcellence.com/aijbes (accessed Mar. 12, 2026).

\[5\] A. R. Santos and J. M. Lee, “Students’ struggle with digital addiction: The impact of short-form content on cognitive performance,” BMC Psychol., vol. 13, no. 1, pp. 112–128, Jan. 2025. \[Online\]. Available: https://bmcpsychology.biomedcentral.com/ (accessed Mar. 12, 2026).

\[6\] “Variable reward schedules (Why habits are addictive),” Cohorty, Feb. 14, 2025. \[Online\]. Available: https://www.cohorty.com/blog/variable-reward-schedules (accessed Mar. 12, 2026).

\[7\] T. V. Reyes and M. C. Delgado, “‘Brain rot’ among university students in the digital age: A longitudinal study on attention span,” PubMed Cent., ID PMC1092834, Feb. 2026. \[Online\]. Available: https://www.ncbi.nlm.nih.gov/pmc/ (accessed Mar. 12, 2026).

\[8\] “Unofficial parental control apps put children’s safety at risk,” Tech Xplore, Jan. 15, 2025. \[Online\]. Available: https://techxplore.com/ (accessed Mar. 12, 2026).

\[9\] K. Purnell, “Philippines among top 3 countries for highest screen time again — data,” Philstar.com, Apr. 19, 2024. \[Online\]. Available: https://www.philstar.com/lifestyle/gadgets/2024/04/19/2348902/philippines-among-top-3-countries-highest-screen-time-again-data (accessed Mar. 12, 2026).

\[10\] “Mandated DNS blocking: Critical considerations,” Internet Society, Jan. 12, 2025. \[Online\]. Available: https://www.internetsociety.org/resources/doc/2025/mandated-dns-blocking/ (accessed Mar. 12, 2026).

\[11\] “An overview of DNS filtering: How it works and why it matters,” RiskRecon, Oct. 05, 2024. \[Online\]. Available: https://www.riskrecon.com/blog/overview-of-dns-filtering (accessed Mar. 12, 2026).

\[12\] “Advancing connectivity in 2023: Trends to watch,” IEEE Transmitter, Dec. 15, 2022. \[Online\]. Available: https://transmitter.ieee.org/ (accessed Mar. 12, 2026).

\[13\] M. Arnold, M. Goldschmitt, and T. Rigotti, “Dealing with information overload: A comprehensive review,” Front. Psychol., vol. 14, pp. 1–15, 2023. \[Online\]. Available: https://www.frontiersin.org/journals/psychology (accessed Mar. 12, 2026).

\[14\] “Doomscrolling and mental health effects: A report on digital behavior,” Digital Behavior Studies Research Reports, vol. 12, no. 4, pp. 210–225, 2025. \[Online\]. Available: https://www.digitalbehaviorstudies.org/reports/2025 (accessed Mar. 12, 2026).

\[15\] L. Chen, “The role of the internet in alleviating poverty: Opportunities and challenges,” Inst. Internet Econ., Research Paper 2025-04, May 2025. \[Online\]. Available: https://www.iie-economics.org/publications (accessed Mar. 12, 2026).

\[16\] Y. Xiao and J. Mann, “Addictive screen use and youth mental health: Trends and interventions,” Weill Cornell Med., Research Brief, 2025. \[Online\]. Available: https://weill.cornell.edu/news (accessed Mar. 12, 2026).

\[17\] J. Taylor, “The impact of internet connectivity on remote work,” Inst. Internet Econ., Apr. 2024. \[Online\]. Available: https://www.iie-economics.org/ (accessed Mar. 12, 2026).

\[18\] “Edge Computing: Moving processing to the network frontier,” Network World, Jan. 10, 2025. \[Online\]. Available: https://www.networkworld.com/ (accessed Mar. 12, 2026).