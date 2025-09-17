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
	IsAdmin  bool   `json:"is_admin" gorm:"default:false"`
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
	UserID  uint `json:"user_id"`
	IsAdmin bool `json:"is_admin"`
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

	// 创建管理员账户
	createAdminUser()
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

func createAdminUser() {
	var admin User
	err := db.Where("username = ?", "admin").First(&admin).Error
	if err != nil {
		// 管理员不存在，创建管理员账户
		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("zhaohao-admin"), bcrypt.DefaultCost)
		adminUser := User{
			Username: "admin",
			Password: string(hashedPassword),
			IsAdmin:  true,
		}
		db.Create(&adminUser)
		log.Println("Admin user created: admin/zhaohao-admin")
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
		UserID:  user.ID,
		IsAdmin: user.IsAdmin,
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
		"is_admin": user.IsAdmin,
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
		c.Set("is_admin", claims.IsAdmin)
		c.Next()
	}
}

// 管理员中间件
func adminMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		isAdmin, exists := c.Get("is_admin")
		if !exists || !isAdmin.(bool) {
			c.JSON(http.StatusForbidden, gin.H{"error": "Admin access required"})
			c.Abort()
			return
		}
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

// 管理员API - 获取所有用户
func adminGetUsers(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	limit := 20
	offset := (page - 1) * limit

	var users []User
	var total int64

	db.Model(&User{}).Count(&total)
	db.Select("id, username, is_admin").Offset(offset).Limit(limit).Find(&users)

	c.JSON(http.StatusOK, gin.H{
		"users":       users,
		"total":       total,
		"page":        page,
		"total_pages": (total + int64(limit) - 1) / int64(limit),
	})
}

// 管理员API - 删除用户
func adminDeleteUser(c *gin.Context) {
	userID := c.Param("id")

	// 不能删除管理员账户
	var user User
	if err := db.First(&user, userID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	if user.IsAdmin {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Cannot delete admin user"})
		return
	}

	// 删除用户及其相关数据
	db.Where("user_id = ?", userID).Delete(&Progress{})
	db.Delete(&user)

	c.JSON(http.StatusOK, gin.H{"message": "User deleted successfully"})
}

// 管理员API - 获取所有词语
func adminGetAllWords(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	limit := 50
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

// 管理员API - 添加词语
func adminAddWord(c *gin.Context) {
	var word Word
	if err := c.ShouldBindJSON(&word); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := db.Create(&word).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Word already exists"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Word added successfully", "word": word})
}

// 管理员API - 更新词语
func adminUpdateWord(c *gin.Context) {
	wordID := c.Param("id")
	var word Word

	if err := db.First(&word, wordID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Word not found"})
		return
	}

	var updateData Word
	if err := c.ShouldBindJSON(&updateData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	word.Word = updateData.Word
	word.Pinyin = updateData.Pinyin
	db.Save(&word)

	c.JSON(http.StatusOK, gin.H{"message": "Word updated successfully", "word": word})
}

// 管理员API - 删除词语
func adminDeleteWord(c *gin.Context) {
	wordID := c.Param("id")
	var word Word

	if err := db.First(&word, wordID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Word not found"})
		return
	}

	db.Delete(&word)
	c.JSON(http.StatusOK, gin.H{"message": "Word deleted successfully"})
}

// 管理员API - 获取所有文章
func adminGetAllArticles(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	limit := 20
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

// 管理员API - 添加文章
func adminAddArticle(c *gin.Context) {
	var article Article
	if err := c.ShouldBindJSON(&article); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := db.Create(&article).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Article title already exists"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Article added successfully", "article": article})
}

// 管理员API - 更新文章
func adminUpdateArticle(c *gin.Context) {
	articleID := c.Param("id")
	var article Article

	if err := db.First(&article, articleID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Article not found"})
		return
	}

	var updateData Article
	if err := c.ShouldBindJSON(&updateData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	article.Title = updateData.Title
	article.Content = updateData.Content
	article.Pinyin = updateData.Pinyin
	db.Save(&article)

	c.JSON(http.StatusOK, gin.H{"message": "Article updated successfully", "article": article})
}

// 管理员API - 删除文章
func adminDeleteArticle(c *gin.Context) {
	articleID := c.Param("id")
	var article Article

	if err := db.First(&article, articleID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Article not found"})
		return
	}

	db.Delete(&article)
	c.JSON(http.StatusOK, gin.H{"message": "Article deleted successfully"})
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

	// 管理员路由
	admin := r.Group("/admin")
	admin.Use(authMiddleware(), adminMiddleware())
	{
		// 用户管理
		admin.GET("/users", adminGetUsers)
		admin.DELETE("/users/:id", adminDeleteUser)

		// 词语管理
		admin.GET("/words", adminGetAllWords)
		admin.POST("/words", adminAddWord)
		admin.PUT("/words/:id", adminUpdateWord)
		admin.DELETE("/words/:id", adminDeleteWord)

		// 文章管理
		admin.GET("/articles", adminGetAllArticles)
		admin.POST("/articles", adminAddArticle)
		admin.PUT("/articles/:id", adminUpdateArticle)
		admin.DELETE("/articles/:id", adminDeleteArticle)
	}

	log.Println("Server starting on :8080")
	r.Run(":8080")
}
