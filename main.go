package main

import (
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jinzhu/gorm"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

var db *gorm.DB
var jwtKey = []byte("your-secret-key")

type User struct {
	ID       uint   `json:"id" gorm:"primary_key"`
	Username string `json:"username" gorm:"unique"`
	Password string `json:"password"`
}

type Progress struct {
	ID       uint   `json:"id" gorm:"primary_key"`
	UserID   uint   `json:"user_id"`
	Type     string `json:"type"` // "word" or "article"
	Page     int    `json:"page"`
	CreateAt time.Time
}

type Word struct {
	ID     uint   `json:"id" gorm:"primary_key"`
	Word   string `json:"word"`
	Pinyin string `json:"pinyin"`
}

type Article struct {
	ID      uint   `json:"id" gorm:"primary_key"`
	Title   string `json:"title"`
	Content string `json:"content"`
	Pinyin  string `json:"pinyin"`
}

type Claims struct {
	UserID uint `json:"user_id"`
	jwt.RegisteredClaims
}

func initDB() {
	var err error
	dbPath := os.Getenv("DATABASE_PATH")
	if dbPath == "" {
		dbPath = "pinyin.db"
	}
	db, err = gorm.Open("sqlite3", dbPath)
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}

	db.AutoMigrate(&User{}, &Progress{}, &Word{}, &Article{})

	// 初始化一些示例数据
	initSampleData()
}

func initSampleData() {
	// 添加示例词语
	words := []Word{
		{Word: "你好", Pinyin: "nǐ hǎo"},
		{Word: "世界", Pinyin: "shì jiè"},
		{Word: "学习", Pinyin: "xué xí"},
		{Word: "拼音", Pinyin: "pīn yīn"},
		{Word: "汉字", Pinyin: "hàn zì"},
		{Word: "中国", Pinyin: "zhōng guó"},
		{Word: "朋友", Pinyin: "péng yǒu"},
		{Word: "家庭", Pinyin: "jiā tíng"},
		{Word: "工作", Pinyin: "gōng zuò"},
		{Word: "学校", Pinyin: "xué xiào"},
		{Word: "老师", Pinyin: "lǎo shī"},
		{Word: "学生", Pinyin: "xué shēng"},
		{Word: "书本", Pinyin: "shū běn"},
		{Word: "电脑", Pinyin: "diàn nǎo"},
		{Word: "手机", Pinyin: "shǒu jī"},
		{Word: "水果", Pinyin: "shuǐ guǒ"},
		{Word: "蔬菜", Pinyin: "shū cài"},
		{Word: "动物", Pinyin: "dòng wù"},
		{Word: "植物", Pinyin: "zhí wù"},
		{Word: "天气", Pinyin: "tiān qì"},
	}

	for _, word := range words {
		var count int64
		db.Model(&Word{}).Where("word = ?", word.Word).Count(&count)
		if count == 0 {
			db.Create(&word)
		}
	}

	// 添加示例文章
	articles := []Article{
		{
			Title:   "春天来了",
			Content: "春天来了，花儿开了。小鸟在树上唱歌，蝴蝶在花丛中飞舞。孩子们在公园里玩耍，到处都是欢声笑语。",
			Pinyin:  "chūn tiān lái le，huā ér kāi le。xiǎo niǎo zài shù shàng chàng gē，hú dié zài huā cóng zhōng fēi wǔ。hái zi men zài gōng yuán lǐ wán shuǎ，dào chù dōu shì huān shēng xiào yǔ。",
		},
		{
			Title:   "我的家",
			Content: "我有一个温暖的家。家里有爸爸、妈妈和我。我们住在一个漂亮的房子里，房子周围有很多绿色的植物。",
			Pinyin:  "wǒ yǒu yī gè wēn nuǎn de jiā。jiā lǐ yǒu bà ba、mā ma hé wǒ。wǒ men zhù zài yī gè piào liàng de fáng zi lǐ，fáng zi zhōu wéi yǒu hěn duō lǜ sè de zhí wù。",
		},
		{
			Title:   "学校生活",
			Content: "我在学校里学习很多知识。老师很友善，同学们也很友好。我们一起学习汉语、数学和科学。",
			Pinyin:  "wǒ zài xué xiào lǐ xué xí hěn duō zhī shi。lǎo shī hěn yǒu shàn，tóng xué men yě hěn yǒu hǎo。wǒ men yī qǐ xué xí hàn yǔ、shù xué hé kē xué。",
		},
	}

	for _, article := range articles {
		var count int64
		db.Model(&Article{}).Where("title = ?", article.Title).Count(&count)
		if count == 0 {
			db.Create(&article)
		}
	}
}

func register(c *gin.Context) {
	var user User
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}

	user.Password = string(hashedPassword)
	if err := db.Create(&user).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Username already exists"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User created successfully"})
}

func login(c *gin.Context) {
	var loginData User
	if err := c.ShouldBindJSON(&loginData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var user User
	if err := db.Where("username = ?", loginData.Username).First(&user).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(loginData.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	expirationTime := time.Now().Add(24 * time.Hour)
	claims := &Claims{
		UserID: user.ID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not create token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"token":    tokenString,
		"user_id":  user.ID,
		"username": user.Username,
	})
}

func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
			c.Abort()
			return
		}

		tokenString := strings.Replace(authHeader, "Bearer ", "", 1)
		claims := &Claims{}

		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		c.Set("user_id", claims.UserID)
		c.Next()
	}
}

func getWords(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	limit := 10
	offset := (page - 1) * limit

	var words []Word
	var total int64

	db.Model(&Word{}).Count(&total)
	db.Offset(offset).Limit(limit).Find(&words)

	c.JSON(http.StatusOK, gin.H{
		"words":       words,
		"total":       total,
		"page":        page,
		"total_pages": (total + int64(limit) - 1) / int64(limit),
	})
}

func getArticles(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	limit := 1
	offset := (page - 1) * limit

	var articles []Article
	var total int64

	db.Model(&Article{}).Count(&total)
	db.Offset(offset).Limit(limit).Find(&articles)

	c.JSON(http.StatusOK, gin.H{
		"articles":    articles,
		"total":       total,
		"page":        page,
		"total_pages": (total + int64(limit) - 1) / int64(limit),
	})
}

func saveProgress(c *gin.Context) {
	userID := c.GetUint("user_id")

	var progressData struct {
		Type string `json:"type"`
		Page int    `json:"page"`
	}

	if err := c.ShouldBindJSON(&progressData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var progress Progress
	db.Where("user_id = ? AND type = ?", userID, progressData.Type).First(&progress)

	if progress.ID == 0 {
		progress = Progress{
			UserID:   userID,
			Type:     progressData.Type,
			Page:     progressData.Page,
			CreateAt: time.Now(),
		}
		db.Create(&progress)
	} else {
		progress.Page = progressData.Page
		db.Save(&progress)
	}

	c.JSON(http.StatusOK, gin.H{"message": "Progress saved"})
}

func getProgress(c *gin.Context) {
	userID := c.GetUint("user_id")
	practiceType := c.Param("type")

	var progress Progress
	db.Where("user_id = ? AND type = ?", userID, practiceType).First(&progress)

	if progress.ID == 0 {
		c.JSON(http.StatusOK, gin.H{"page": 1})
	} else {
		c.JSON(http.StatusOK, gin.H{"page": progress.Page})
	}
}

func main() {
	initDB()
	defer db.Close()

	r := gin.Default()

	// 启用CORS
	r.Use(func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Origin, Content-Type, Authorization")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	})

	// 公开路由
	r.POST("/register", register)
	r.POST("/login", login)

	// 需要认证的路由
	auth := r.Group("/api")
	auth.Use(authMiddleware())
	{
		auth.GET("/words", getWords)
		auth.GET("/articles", getArticles)
		auth.POST("/progress", saveProgress)
		auth.GET("/progress/:type", getProgress)
	}

	log.Println("Server starting on :8080")
	r.Run(":8080")
}
