var tentaclesArray;
var tNamesByIdArray;
var tIPByIdArray;
var scriptsIdArray;
var sNamesByIdArray;
var tHasS;
var sHasT;
var resultsArray;
var tentacleId;

function updateTentacleScriptLink() {
	$.ajax({
		url : 'service?action=gettentaclescripts&key='+encodeURIComponent(key)+'&id='+encodeURIComponent(id),
		type : 'GET',
		success : function(data){
			if(data.success == "logout"){
				key=0;
				id=0;
				$("#pages").hide();
				$("#login").show();
				$("#loginMsg").text("Disconnected (inactivity)");
				$("#loginMsg").slideDown();
			}else if(data.success){
				scriptsIdArray = new Array();
				sNamesByIdArray = new Array();
				sHasT = new Array();
				tHasS = new Array();
				$(".errMsg").slideUp();
				var i;
				for (i = 0; i < data.scripts.length; ++i) {
					scriptsIdArray.push(data.scripts[i].id);
					sNamesByIdArray[data.scripts[i].id] = data.scripts[i].name;
					sHasT[data.scripts[i].id] = new Array();
					var j;
					for(j = 0; j < data.scripts[i].tentacles.length;++j){
						if(data.scripts[i].tentacles[j].has){
							sHasT[data.scripts[i].id].push(data.scripts[i].tentacles[j].id);
							if (typeof tHasS[data.scripts[i].tentacles[j].id] === 'undefined') {
								tHasS[data.scripts[i].tentacles[j].id] = new Array;
							}
							tHasS[data.scripts[i].tentacles[j].id].push(data.scripts[i].id);
						}
					}
				}
			}else{
				$("#errorField").text("Either there are no scripts in that tentacle or there is a connection problem to the brain. Please try again.");
				$(".errMsg").slideDown();
			}
		},
		error : function(jqXHR, textStatus, errorThrown ){
			alert("Error !" + textStatus + " > " + errorThrown);
		}
	});
}
function updateTentacleList(){
	$.ajax({
		url : 'service?action=gettentacles&key='+encodeURIComponent(key)+'&id='+encodeURIComponent(id),
		type : 'GET',
		success : function(data){
			if(data.success == "logout"){
				key=0;
				id=0;
				$("#pages").hide();
				$("#login").show();
				$("#loginMsg").text("Disconnected (inactivity)");
				$("#loginMsg").slideDown();
			}else if(data.success){
				tentaclesArray = new Array();
				tNamesByIdArray = new Array();
				tIPByIdArray = new Array();

				$(".errMsg").slideUp();
				var i;
				var content="";
				updateTentacleScriptLink();
				tentaclesArray = data.tentacles;
				for (i = 0; i < tentaclesArray.length; ++i) {
					tNamesByIdArray[tentaclesArray[i].id] = tentaclesArray[i].hostname;
					tIPByIdArray[tentaclesArray[i].id] = tentaclesArray[i].ip;
					lastalive = new Date((tentaclesArray[i].lastalive)*1000);
					content += "<tr><td><a href='#' id='"+tentaclesArray[i].id+"' class='tentacleDetailLink'>"+tentaclesArray[i].hostname+"</a></td><td>"+tentaclesArray[i].ip+"</td><td>"+lastalive.toString()+"</td>";
					content += "</tr>";
				}
				$("#tentacleList").html(content);
			}else{
				$("#errorField").text("Either there are no tentacles registered or there is a connection problem to the brain. Please try again.");
				$(".errMsg").slideDown();
			}
		},
		error : function(jqXHR, textStatus, errorThrown ){
			alert("Error !" + textStatus + " > " + errorThrown);
		}
	});
}
function updateScriptList(){
	updateTentacleScriptLink();
	var i;
	var content="";
	$(".errMsg").slideUp();
	for (i = 0; i < scriptsIdArray.length; ++i) {
		content += "<tr><td><a href='#' id='"+scriptsIdArray[i]+"' class='scriptDetailLink'>"+sNamesByIdArray[scriptsIdArray[i]]+"</a></td></tr>";
	}
	$("#scriptList").html(content);
}
function updateResultsList(){
	$.ajax({
		url : 'service?action=getscriptsresults&key='+encodeURIComponent(key)+'&id='+encodeURIComponent(id),
		type : 'GET',
		success : function(data){
			if(data.success == "logout"){
				key=0;
				id=0;
				$("#pages").hide();
				$("#login").show();
				$("#loginMsg").text("Disconnected (inactivity)");
				$("#loginMsg").slideDown();
			}else if(data.success){
				resultsArray = new Array();
				$(".errMsg").slideUp();
				var i;
				resultsArray = data.results;
				var content = "";
				for (i = 0; i < resultsArray.length; ++i) {
					var datetime = resultsArray[i].date.toString();
					content += "<fieldset>";
					content += "<legend>Commande <strong>"+resultsArray[i].script+"</strong> lancée sur <strong>"+tNamesByIdArray[resultsArray[i].tentacle]+"</strong> - date : "+datetime.substring(0,4)+"-"+datetime.substring(4,6)+"-"+datetime.substring(6,8)+" "+datetime.substring(8,10)+":"+datetime.substring(10,12)+":"+datetime.substring(12,14);
					content += "<a class='pull-right' data-toggle='collapse' href='#result"+i+"' aria-expanded='false' aria-controls='result"+i+"'>Afficher</a></legend>";
					content += "<pre class='collapse' id='result"+i+"'>"+decodeURIComponent(resultsArray[i].result).replace(/\+/g," ")+"</pre>";
					content += "</fieldset>";
				}
				$("#resultsList").html(content);
			}else{
				$("#errorField").text("Either there are no results registered or there is a connection problem to the brain. Please try again.");
				$(".errMsg").slideDown();
			}
		},
		error : function(jqXHR, textStatus, errorThrown ){
			alert("Error !" + textStatus + " > " + errorThrown);
		}
	});
}

$("#loginButton").click( function(){
	$(".winMsg").slideUp();
	$(".errMsg").slideUp();
	var login = $("#user").val();
	var pw = $("#pass").val();
	$("#loginMsg").slideUp();
	$.ajax({
		url : 'service?action=login&login='+encodeURIComponent(login)+'&pw='+encodeURIComponent(pw),
		type : 'GET',
		success : function(data){
			if(data.success == "logout"){
				key=0;
				id=0;
				$("#pages").hide();
				$("#login").show();
				$("#loginMsg").text("Disconnected (inactivity)");
				$("#loginMsg").slideDown();
			}else if(data.success){
				key = data.key;
				username = data.login;
				id = data.id;
				$("input").val("");
				$("#usernameField").text(username);
				$(".page").hide();
				$("#pages").show();
				$("#network").show();
				updateTentacleList();
			}else{
				$("#loginMsg").text("Unable to connect");
				$("#loginMsg").slideDown();
			}
		},
		error : function(jqXHR, textStatus, errorThrown ){
			alert("Error !" + textStatus + " > " + errorThrown);
		}
	});
	return false;
});

$("#logoutButton").click( function(){
	$("#pages").hide();
	$(".winMsg").slideUp();
	$("#login").show();
	return false;
});
function updateTentacleDetail() {
	var content="";
	updateTentacleScriptLink();
	$("#tentacleDetail-hostname").html(tNamesByIdArray[tentacleId]);
	$("#tentacleDetail-ip").html(tIPByIdArray[tentacleId]);
	$(".errMsg").slideUp();
	for (i = 0; i < scriptsIdArray.length; ++i) {
		content += "<tr><td>"+sNamesByIdArray[scriptsIdArray[i]]+"</td><td>";

		if(typeof(tHasS[tentacleId]) !== "undefined" && tHasS[tentacleId].indexOf(scriptsIdArray[i]) >= 0){
			content += "<a href='#' id='"+scriptsIdArray[i]+"' class='tentacleScriptRun btn btn-success'>Lancer <span class='glyphicon glyphicon-circle-arrow-right' aria-hidden='true'></span></a>"
		}else{
			content += "<a href='#' id='"+scriptsIdArray[i]+"' class='tentacleScriptAdd btn btn-danger'>Ajouter <span class='glyphicon glyphicon-plus-sign' aria-hidden='true'></span></a>"
		}

		content += "</td></tr>";
	}
	$("#tentacleDetail-scriptList").html(content);
}

$("table").on('click', 'a.tentacleDetailLink', function() {
	$(".winMsg").slideUp();
	tentacleId = $(this).attr('id');
	updateTentacleDetail();
	$(".page").hide();
	$("#tentacleDetail").show();
	return false;
});

$("table").on('click', 'a.tentacleScriptRun', function() {
	$(".winMsg").slideUp();
	var content;
	$.ajax({
		url : 'service?action=runscript&key='+encodeURIComponent(key)+'&id='+encodeURIComponent(id)+"&tentacle="+tentacleId+"&script="+$(this).attr('id'),
		type : 'GET',
		success : function(data){
			if(data.success == "logout"){
				key=0;
				id=0;
				$("#pages").hide();
				$("#login").show();
				$("#loginMsg").text("Disconnected (inactivity)");
				$("#loginMsg").slideDown();
			}else if(data.success){
				$(".errMsg").slideUp();
				$("#winField").text("Script successfully launched.");
				$(".winMsg").slideDown();
			}else{
				$(".winMsg").slideUp();
				$("#errorField").text("Couldn't run script. Please try again.");
				$(".errMsg").slideDown();
			}
		},
		error : function(jqXHR, textStatus, errorThrown ){
			alert("Error !" + textStatus + " > " + errorThrown);
		}
	});
	sleep(100);
	
	updateTentacleDetail();

	return false;
});

$("table").on('click', 'a.tentacleScriptAdd', function() {
	$(".winMsg").slideUp();
	var content;
	$.ajax({
		url : 'service?action=cpyscript&key='+encodeURIComponent(key)+'&id='+encodeURIComponent(id)+"&tentacle="+tentacleId+"&script="+$(this).attr('id'),
		type : 'GET',
		success : function(data){
			if(data.success == "logout"){
				key=0;
				id=0;
				$("#pages").hide();
				$("#login").show();
				$("#loginMsg").text("Disconnected (inactivity)");
				$("#loginMsg").slideDown();
			}else if(data.success){
				$(".errMsg").slideUp();
				$("#winField").text("Script successfully added.");
				$(".winMsg").slideDown();
			}else{
				$(".winMsg").slideUp();
				$("#errorField").text("Couldn't run script. Please try again.");
				$(".errMsg").slideDown();
			}
		},
		error : function(jqXHR, textStatus, errorThrown ){
			alert("Error !" + textStatus + " > " + errorThrown);
		}
	});

	updateTentacleScriptLink();
	updateTentacleDetail();
	$("#tentacleDetail").show();
	return false;
});



$("#linkNetwork").click( function(){
	$(".winMsg").slideUp();
	$(".errMsg").slideUp();
	$(".navLinks").removeClass("active");
	$("#navNetwork").addClass("active");
	$(".page").hide();
	$("#network").show();
	updateTentacleList();
	return false;
});
$("#linkResults").click( function(){
	$(".winMsg").slideUp();
	$(".errMsg").slideUp();
	$(".navLinks").removeClass("active");
	$("#navResults").addClass("active");
	$(".page").hide();
	$("#results").show();
	updateResultsList();
	return false;
});
$("#linkScripts").click( function(){
	$(".winMsg").slideUp();
	$(".errMsg").slideUp();
	$(".navLinks").removeClass("active");
	$("#navScripts").addClass("active");
	$(".page").hide();
	$("#scripts").show();
	updateScriptList();
	return false;
});


$("#addTentacleButton").click( function(){
	$('#modalAddTentacle').modal('hide');
	$(".winMsg").slideUp();
	$(".errMsg").slideUp();

	var ip = $("#ip").val();
	$.ajax({
		url : 'service?action=addtentacle&ip='+encodeURIComponent(ip)+'&key='+encodeURIComponent(key)+'&id='+encodeURIComponent(id),
		type : 'GET',
		success : function(data){
			if(data.success == "logout"){
				key=0;
				id=0;
				$("#pages").hide();
				$("#login").show();
				$("#loginMsg").text("Disconnected (inactivity)");
				$("#loginMsg").slideDown();
			}else if(data.success){
				$(".errMsg").slideUp();
				updateTentacleList();
			}else{
				$("#errorField").text("Unable to add tentacle : please try again.");
				$(".errMsg").slideDown();
			}
		},
		error : function(jqXHR, textStatus, errorThrown ){
			alert("Error !" + textStatus + " > " + errorThrown);
		}
	});
	return false;
});


$("#addScriptButton").click( function(){
	$('#modalAddScript').modal('hide');
	$(".errMsg").slideUp();
	$(".winMsg").slideUp();

	var name = $("#addScriptName").val();
	var content = $("#addScriptContent").val();
	$.ajax({
		url : 'service?action=addscript&name='+encodeURIComponent(name)+'&content='+encodeURIComponent(content)+'&key='+encodeURIComponent(key)+'&id='+encodeURIComponent(id),
		type : 'GET',
		success : function(data){
			if(data.success == "logout"){
				key=0;
				id=0;
				$("#pages").hide();
				$("#login").show();
				$("#loginMsg").text("Disconnected (inactivity)");
				$("#loginMsg").slideDown();
			}else if(data.success){
				$(".errMsg").slideUp();
				updateTentacleList();
			}else{
				$("#errorField").text("Unable to add tentacle : please try again.");
				$(".errMsg").slideDown();
			}
		},
		error : function(jqXHR, textStatus, errorThrown ){
			alert("Error !" + textStatus + " > " + errorThrown);
		}
	});
	return false;
});


